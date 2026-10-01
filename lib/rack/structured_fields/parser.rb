# frozen_string_literal: true

module Rack
  module StructuredFields
    class Parser
      BASE64_ALPHABET = ("A".."Z").to_a + ("a".."z").to_a + ("0".."9").to_a + ['+', '/']
      BASE64_BYTES = BASE64_ALPHABET.map(&:ord).freeze
      BASE64_STRICT = /\A(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?\z/
      TOKEN_EXTRA_BYTES = "!#$%&'*+-.".bytes.freeze
      TOKEN_SYMBOL_BYTES = '^_|~:/'.bytes.freeze
      KEY_EXTRA_BYTES = '_-.'.bytes.freeze

      def initialize(input)
        unless input.is_a?(String)
          raise ParseError, "Structured Field input must be a String"
        end

        @input = input.b
        @position = 0
      end

      def parse(shape)
        unless SHAPES.include?(shape)
          raise ArgumentError, "unknown Structured Field shape #{shape.inspect}"
        end

        result =
          case shape
          when :item then parse_top_level_item
          when :list then parse_list
          when :dictionary then parse_dictionary
          end

        finish
        result
      end

      private

      def parse_top_level_item
        item = parse_item
        skip_ows
        item
      end

      def parse_list
        entries = []
        skip_ows

        unless eof?
          entries << parse_list_member

          loop do
            skip_ows
            break if eof?
            expect_byte!(',')
            skip_ows
            error!("expected list member") if eof?
            entries << parse_list_member
          end
        end

        entries
      end

      def parse_dictionary
        members = {}
        skip_ows

        unless eof?
          members.merge!(parse_dictionary_member)

          loop do
            skip_ows
            break if eof?
            expect_byte!(',')
            skip_ows
            error!("expected dictionary member") if eof?
            member = parse_dictionary_member
            if members.key?(member.keys.first)
              error!("duplicate dictionary key", @duplicate_position)
            end
            members.merge!(member)
          end
        end

        members
      end

      def parse_list_member
        peek_byte == '('.ord ? parse_inner_list : parse_item
      end

      def parse_dictionary_member
        start = @position
        @duplicate_position = start
        key = parse_key

        if consume_byte?('=')
          value =
            if peek_byte == '('.ord
              parse_inner_list
            else
              bare_item = parse_bare_item
              parameters = parse_parameters
              parameters.empty? ? bare_item : Item.new(bare_item, parameters)
            end
        else
          parameters = parse_parameters
          value = parameters.empty? ? true : Item.new(true, parameters)
        end

        { key => value }
      end

      def parse_inner_list
        expect_byte!('(')
        entries = []

        unless peek_byte == ')'.ord
          entries << parse_item

          until peek_byte == ')'.ord
            error!("unterminated inner list") if eof?
            expect_byte!(' ')
            entries << parse_item
          end
        end

        expect_byte!(')')
        InnerList.new(entries, parse_parameters)
      end

      def parse_item
        Item.new(parse_bare_item, parse_parameters)
      end

      def parse_parameters
        parameters = {}

        while peek_byte == ' '.ord && byte_at(@position + 1) == ';'.ord
          @position += 2
          expect_byte!(' ')
          start = @position
          key = parse_key
          value = consume_byte?('=') ? parse_bare_item : true

          if parameters.key?(key)
            error!("duplicate parameter key", start)
          end

          parameters[key] = value
        end

        parameters
      end

      def parse_bare_item
        byte = peek_byte

        case byte
        when '-'.ord, *('0'.ord..'9'.ord)
          parse_number
        when '"'.ord
          parse_string
        when '?'.ord
          parse_boolean
        when ':'.ord
          parse_byte_sequence
        when '%'.ord
          parse_display_string
        when '@'.ord
          parse_date
        else
          if token_start?(byte)
            parse_token
          else
            error!("expected bare item")
          end
        end
      end

      def parse_number
        start = @position
        consume_byte?('-')
        digits_start = @position
        integer_digits = consume_digits
        error!("expected integer or decimal") if integer_digits.zero?

        if peek_byte == '.'.ord
          @position += 1
          fraction_start = @position
          fraction_digits = consume_digits
          error!("expected decimal fraction", fraction_start) if fraction_digits.zero?

          if integer_digits > 12
            error!("integer part of decimal is out of range", digits_start)
          end

          if fraction_digits > 3
            error!("decimal fraction cannot contain more than 3 digits", fraction_start + 3)
          end

          @input.byteslice(start...@position).to_f
        else
          if integer_digits > 15
            error!("integer is out of range", digits_start + 15)
          end

          @input.byteslice(start...@position).to_i
        end
      end

      def parse_date
        start = @position
        @position += 1
        consume_byte?('-')
        digits_start = @position
        digits = consume_digits
        error!("expected date integer") if digits.zero?

        if digits > 15
          error!("date is out of range", digits_start + 15)
        end

        Date.new(@input.byteslice(start + 1...@position).to_i)
      end

      def parse_boolean
        position = @position + 1
        @position += 1

        case read_byte!
        when '1'.ord
          true
        when '0'.ord
          false
        else
          error!("expected boolean", position)
        end
      end

      def parse_string
        expect_byte!('"')
        output = String.new.b

        loop do
          byte = read_byte!

          case byte
          when '"'.ord
            return output.force_encoding(Encoding::UTF_8)
          when '\\'.ord
            escaped = read_byte!
            unless escaped == '"'.ord || escaped == '\\'.ord
              error!("invalid string escape", @position - 2)
            end

            output << escaped
          when ' '.ord..'!'.ord, '#'.ord..'['.ord, ']'.ord..'~'.ord
            output << byte
          else
            error!("invalid string character", @position - 1)
          end
        end
      end

      def parse_token
        start = @position

        while token_byte?(peek_byte)
          @position += 1
        end

        Token.new(@input.byteslice(start...@position))
      end

      def parse_byte_sequence
        expect_byte!(':')
        content_start = @position
        closing = @input.index(':'.ord.chr.b, @position)
        error!("unterminated byte sequence") unless closing

        content = @input.byteslice(content_start...closing)
        content.each_byte.with_index(content_start) do |byte, position|
          unless BASE64_BYTES.include?(byte) || byte == '='.ord
            error!("invalid base64 character", position)
          end
        end

        unless BASE64_STRICT.match?(content)
          padding_start = content.index('=')
          position = padding_start ? content_start + padding_start : content_start
          error!("invalid base64 padding", position)
        end

        begin
          decoded = content.unpack1('m0')
        rescue ArgumentError
          error!("invalid base64 sequence", content_start)
        end

        @position = closing + 1
        ByteSequence.new(decoded)
      end

      def parse_display_string
        expect_byte!('%')
        expect_byte!('"')
        output = String.new.b
        sequence_start = nil

        loop do
          position = @position
          raw_byte = read_byte!

          if raw_byte == '"'.ord
            output.force_encoding(Encoding::UTF_8)
            unless output.valid_encoding?
              error!("invalid UTF-8 in display string", sequence_start || position)
            end

            return DisplayString.new(output)
          end

          encoded = raw_byte == '%'.ord
          byte = encoded ? read_percent_byte : raw_byte

          if byte >= 0x80
            sequence_start ||= position
            output << append_utf8_continuation(byte, sequence_start, @position)
            sequence_start = nil
          elsif !encoded && display_ascii?(byte)
            sequence_start = nil
            output << byte
          elsif encoded && byte >= 0x20 && byte <= 0x7E
            sequence_start = nil
            output << byte
          else
            error!("invalid display string character", @position - 1)
          end
        end
      end

      def parse_key
        start = @position
        first = peek_byte

        unless key_start?(first)
          error!("expected dictionary key")
        end

        @position += 1
        while key_byte?(peek_byte)
          @position += 1
        end

        @input.byteslice(start...@position).force_encoding(Encoding::UTF_8)
      end

      def read_display_byte
        byte = read_byte!

        return read_percent_byte if byte == '%'.ord

        byte
      end

      def read_percent_byte
        high = read_hex_digit
        low = read_hex_digit
        (high << 4) | low
      end

      def read_hex_digit
        byte = read_byte!

        case byte
        when '0'.ord..'9'.ord
          byte - '0'.ord
        when 'A'.ord..'F'.ord
          byte - 'A'.ord + 10
        when 'a'.ord..'f'.ord
          byte - 'a'.ord + 10
        else
          error!("invalid percent-encoded byte")
        end
      end

      def append_utf8_continuation(lead, start, continuation_start = @position)
        length, minimum, maximum = utf8_sequence_bounds(lead, start)
        output = String.new.b << lead

        (length - 1).times do |index|
          byte_position = index.zero? ? continuation_start : @position
          raw_byte = read_byte!
          encoded = raw_byte == '%'.ord
          byte = encoded ? read_percent_byte : raw_byte
          unless byte >= 0x80 && byte <= 0xBF
            error!("invalid UTF-8 continuation byte", byte_position)
          end

          if index.zero? && (byte < minimum || byte > maximum)
            error!("overlong or out-of-range UTF-8 sequence", start)
          end

          output << byte
        end

        output
      end

      def utf8_sequence_bounds(byte, start)
        case byte
        when 0xC2..0xDF
          [2, 0x80, 0xBF]
        when 0xE0
          [3, 0xA0, 0xBF]
        when 0xE1..0xEC
          [3, 0x80, 0xBF]
        when 0xED
          [3, 0x80, 0x9F]
        when 0xEE..0xEF
          [3, 0x80, 0xBF]
        when 0xF0
          [4, 0x90, 0xBF]
        when 0xF1..0xF3
          [4, 0x80, 0xBF]
        when 0xF4
          [4, 0x80, 0x8F]
        else
          error!("invalid UTF-8 leading byte", start)
        end
      end

      def consume_digits
        count = 0

        while peek_byte >= '0'.ord && peek_byte <= '9'.ord
          @position += 1
          count += 1
        end

        count
      end

      def skip_ows
        @position += 1 while peek_byte == ' '.ord || peek_byte == "\t".ord
      end

      def token_start?(byte)
        (byte >= 'A'.ord && byte <= 'Z'.ord) ||
          (byte >= 'a'.ord && byte <= 'z'.ord) ||
          byte == '*'.ord
      end

      def token_byte?(byte)
        token_start?(byte) ||
          (byte >= '0'.ord && byte <= '9'.ord) ||
          TOKEN_EXTRA_BYTES.include?(byte) || byte == 0x60 || TOKEN_SYMBOL_BYTES.include?(byte)
      end

      def key_start?(byte)
        (byte >= 'a'.ord && byte <= 'z'.ord) || byte == '*'.ord
      end

      def key_byte?(byte)
        key_start?(byte) ||
          (byte >= '0'.ord && byte <= '9'.ord) ||
          KEY_EXTRA_BYTES.include?(byte)
      end

      def display_ascii?(byte)
        byte == ' '.ord ||
          (byte >= '!'.ord && byte <= '~'.ord &&
            byte != '"'.ord && byte != '%'.ord)
      end

      def peek_byte
        byte_at(@position)
      end

      def byte_at(position)
        @input.getbyte(position) || -1
      end

      def read_byte!
        byte = peek_byte
        error!("unexpected end of input") if byte == -1
        @position += 1
        byte
      end

      def expect_byte!(character)
        error!("expected #{character.inspect}") unless peek_byte == character.ord
        @position += 1
      end

      def consume_byte?(character)
        if peek_byte == character.ord
          @position += 1
          true
        else
          false
        end
      end

      def finish
        error!("unexpected trailing bytes") unless eof?
      end

      def eof?
        @position >= @input.bytesize
      end

      def error!(message, position = @position)
        raise ParseError.new(message, position)
      end
    end
  end
end
