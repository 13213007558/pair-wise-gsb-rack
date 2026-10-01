# frozen_string_literal: true

require_relative 'bad_request'

module Rack
  # RFC 9651 Structured Fields parser and canonical serializer.
  #
  # Callers explicitly choose parse_item/parse_list/parse_dictionary and the
  # matching serialize methods. Parsed decimals use Decimal to preserve their
  # exact scale-independent value; token, byte sequence, date and display
  # string bare values use their corresponding wrapper classes.
  module StructuredFields
    class ParseError < ArgumentError
      include BadRequest

      attr_reader :position

      def initialize(message, position)
        @position = position
        super("#{message} at byte position #{position}")
      end
    end

    class StructuredFieldError < ArgumentError
    end

    class Item
      attr_reader :value, :parameters

      def initialize(value, parameters = {})
        @value = value
        @parameters = parameters
      end

      def ==(other)
        other.is_a?(Item) && value == other.value && parameters == other.parameters
      end
      alias eql? ==

      def hash
        [Item, value, parameters].hash
      end
    end

    class InnerList
      attr_reader :items, :parameters

      def initialize(items = [], parameters = {})
        @items = items
        @parameters = parameters
      end

      def ==(other)
        other.is_a?(InnerList) && items == other.items && parameters == other.parameters
      end
      alias eql? ==

      def hash
        [InnerList, items, parameters].hash
      end
    end

    class Token
      attr_reader :value

      def initialize(value)
        @value = value
      end

      def ==(other)
        other.is_a?(Token) && value == other.value
      end
      alias eql? ==

      def hash
        [Token, value].hash
      end
    end

    class ByteSequence
      attr_reader :value

      def initialize(value)
        @value = value
      end

      def ==(other)
        other.is_a?(ByteSequence) && value == other.value
      end
      alias eql? ==

      def hash
        [ByteSequence, value].hash
      end
    end

    class SFDate
      attr_reader :value

      def initialize(value)
        @value = value
      end

      def ==(other)
        other.is_a?(SFDate) && value == other.value
      end
      alias eql? ==

      def hash
        [SFDate, value].hash
      end
    end


    class DisplayString
      attr_reader :value

      def initialize(value)
        @value = value
      end

      def ==(other)
        other.is_a?(DisplayString) && value == other.value
      end
      alias eql? ==

      def hash
        [DisplayString, value].hash
      end
    end

    class Decimal
      attr_reader :value, :scale

      def initialize(value, scale = nil)
        if scale
          @value = Integer(value)
          @scale = Integer(scale)
          raise ArgumentError, "invalid decimal scale" unless @scale >= 0
        else
          text = value.to_s
          negative = text.start_with?("-")
          integer_part, fractional_part = text.delete_prefix("-").split(".", 2)
          raise ArgumentError, "invalid decimal" unless integer_part && integer_part.match?(/\A[0-9]+\z/)
          raise ArgumentError, "invalid decimal" if fractional_part && !fractional_part.match?(/\A[0-9]+\z/)

          digits = integer_part + (fractional_part || "0")
          @value = Integer(digits, 10) * (negative ? -1 : 1)
          @scale = fractional_part ? fractional_part.length : 0
        end
        freeze
      end

      def ==(other)
        if other.is_a?(Decimal)
          rational == other.rational
        elsif other.is_a?(Numeric)
          rational == other
        else
          false
        end
      end
      alias eql? ==

      def hash
        rational.hash
      end

      def rational
        Rational(value, 10 ** scale)
      end

      def to_r
        rational
      end

      def to_f
        value.to_f / (10 ** scale)
      end

      def to_i
        value / (10 ** scale)
      end

      def to_s
        digits = value.abs.to_s.rjust(scale + 1, "0")
        sign = value.negative? ? "-" : ""
        return "#{sign}#{digits}" if scale.zero?

        integer_part, fractional_part = digits[0...-scale], digits[-scale..]
        fractional_part = fractional_part.sub(/0+\z/, "")
        fractional_part = "0" if fractional_part.empty?
        "#{sign}#{integer_part}.#{fractional_part}"
      end
      alias inspect to_s
    end

    module_function

    def parse_item(field)
      Parser.new(field).parse_item
    end

    def parse_list(field)
      Parser.new(field).parse_list
    end

    def parse_dictionary(field)
      Parser.new(field).parse_dictionary
    end
    alias decode_item parse_item
    alias decode_list parse_list
    alias decode_dictionary parse_dictionary
    module_function :decode_item, :decode_list, :decode_dictionary

    def serialize_item(item)
      item = Item.new(item) unless item.is_a?(Item)
      Serializer.new.serialize_item(item)
    end

    def serialize_list(list)
      raise StructuredFieldError, "expected an Array" unless list.is_a?(Array)

      Serializer.new.serialize_list(list)
    end

    def serialize_dictionary(dictionary)
      Serializer.new.serialize_dictionary(dictionary)
    end
    alias encode_item serialize_item
    alias encode_list serialize_list
    alias encode_dictionary serialize_dictionary
    module_function :encode_item, :encode_list, :encode_dictionary

    class Parser
      TOKEN_START = /[A-Za-z*]/n
      TOKEN_CHARS = %r{[A-Za-z0-9.!#$%&'*+\^_`|~:/\-]}n
      KEY_START = /[a-z*]/n
      KEY_CHARS = /[a-z0-9_\-.*]/n
      BASE64_CHARS = /\A[A-Za-z0-9+\/]*={0,2}\z/n

      def initialize(field)
        raise ParseError.new("expected a String", 0) unless field.is_a?(String)

        @field = field.dup.force_encoding(Encoding::BINARY)
        @position = 0
      end

      def parse_item
        item = read_item
        error!("unexpected trailing data", @position) unless at_end?
        item
      end

      def parse_list
        skip_ows
        return [] if at_end?

        members = []
        loop do
          members << read_list_member
          skip_ows
          break if at_end?

          error!("expected comma", @position) unless consume(",")
          skip_ows
          error!("unexpected trailing comma", @position) if at_end?
        end
        members
      end

      def parse_dictionary
        skip_ows
        return {} if at_end?

        result = {}
        loop do
          key_position = @position
          key = read_key
          key_parameters = read_parameters
          member = if consume("=")
            value = read_list_member
            case value
            when Item
              reject_duplicate_parameters(key_parameters, value.parameters, key_position)
              Item.new(value.value, key_parameters.merge(value.parameters))
            when InnerList
              reject_duplicate_parameters(key_parameters, value.parameters, key_position)
              InnerList.new(value.items, key_parameters.merge(value.parameters))
            else
              Item.new(value, key_parameters)
            end
          elsif key_parameters.empty?
            true
          else
            Item.new(true, key_parameters)
          end

          error!("duplicate dictionary key", key_position) if result.key?(key)
          result[key] = member

          skip_ows
          break if at_end?

          error!("expected comma", @position) unless consume(",")
          skip_ows
          error!("unexpected trailing comma", @position) if at_end?
        end
        result
      end

      private

      def read_list_member
        if peek == "("
          read_inner_list
        else
          read_item
        end
      end

      def read_item
        Item.new(read_bare_item, read_parameters)
      end

      def read_inner_list
        consume!("(")
        items = []
        skip_spaces

        until peek == ")"
          items << read_item
          unless peek == ")"
            position = @position
            skip_spaces
            error!("expected space", position) if @position == position
          end
        end

        consume!(")")
        InnerList.new(items, read_parameters)
      end

      def read_parameters
        parameters = {}
        while consume(";")
          skip_spaces
          position = @position
          key = read_key
          value = consume("=") ? read_bare_item : true
          error!("duplicate parameter key", position) if parameters.key?(key)
          parameters[key] = value
        end
        parameters
      end

      def read_key
        start = @position
        character = advance
        error!("expected key", start) unless character&.match?(KEY_START)

        while (character = peek)&.match?(KEY_CHARS)
          advance
        end
        slice(start, @position).force_encoding(Encoding::UTF_8)
      end

      def read_bare_item
        case peek
        when "-", /[0-9]/n
          read_number
        when '"'
          read_string
        when "%"
          read_display_string
        when "?"
          read_boolean
        when ":"
          read_byte_sequence
        when "@"
          read_date
        when TOKEN_START
          read_token
        else
          error!(@position == @field.bytesize ? "unexpected end of field" : "invalid item", @position)
        end
      end

      def read_number
        start = @position
        consume("-")
        integer_start = @position
        integer_digits = read_digits

        if peek == "."
          advance
          fraction_start = @position
          fraction_digits = read_digits
          error!("expected number", start) if integer_digits.zero?
          error!("expected decimal fraction", fraction_start) if fraction_digits.zero?
          error!("integer part out of range", start) if integer_digits > 12
          error!("fractional part out of range", fraction_start + 3) if fraction_digits > 3
          Decimal.new(slice(start, @position))
        else
          if integer_digits.zero?
            error!("expected number", start)
          elsif integer_digits > 15
            error!("integer out of range", integer_start + 15)
          end
          Integer(slice(start, @position), 10)
        end
      end

      def read_digits
        count = 0
        while peek&.match?(/[0-9]/n)
          advance
          count += 1
        end
        count
      end

      def read_boolean
        consume!("?")
        position = @position
        case advance
        when "1"
          true
        when "0"
          false
        else
          error!("invalid boolean", position)
        end
      end

      def read_date
        consume!("@")
        start = @position
        consume("-")
        digits = read_digits
        error!("expected date", start) if digits.zero?
        error!("date out of range", start + 15) if digits > 15
        SFDate.new(Integer(slice(start, @position), 10))
      end

      def read_token
        start = @position
        error!("expected token", start) unless advance&.match?(TOKEN_START)
        while peek&.match?(TOKEN_CHARS)
          advance
        end
        Token.new(slice(start, @position).force_encoding(Encoding::UTF_8))
      end

      def read_string
        start = @position
        consume!('"')
        entries = []

        loop do
          position = @position
          character = advance
          error!("unterminated string", start) if character.nil?

          if character == '"'
            return String.new(build_utf8(entries), encoding: Encoding::UTF_8)
          elsif character == "\\"
            escaped = advance
            error!("invalid string escape", position) unless escaped == '"' || escaped == "\\"
            entries << [escaped, position]
          elsif character == "%" || character.ord < 0x20 || character.ord == 0x7F
            error!("invalid string character", position)
          else
            entries.concat(read_utf8_entry(character, position, true, :advance))
          end
        end
      end

      def read_display_string
        start = @position
        consume!("%")
        consume!('"')
        entries = []

        loop do
          position = @position
          character = advance
          error!("unterminated display string", start) if character.nil?

          if character == '"' && peek == '%'
            advance
            return DisplayString.new(build_utf8(entries))
          elsif character == '"'
            error!("invalid display string character", position)
          elsif character == "%"
            byte = read_percent_byte
            if byte.ord < 0x80
              entries << [byte, position]
            else
              entries.concat(read_utf8_entry(byte, position, false, :read_display_continuation_byte))
            end
          elsif character.ord >= 0x21 && character.ord <= 0x7E
            entries << [character, position]
          else
            entries.concat(read_utf8_entry(character, position, false, :read_display_continuation_byte))
          end
        end
      end

      def read_percent_byte
        position = @position
        high = advance
        low = advance
        unless high&.match?(/[0-9A-Fa-f]/n) && low&.match?(/[0-9A-Fa-f]/n)
          error!("invalid percent encoding", position)
        end
        Integer(high + low, 16).chr(Encoding::BINARY)
      end

      def read_utf8_entry(first, position, allow_low_ascii, reader)
        ordinal = first.ord
        if ordinal < 0x80
          return [[first, position]] if allow_low_ascii

          error!("invalid display string character", position)
        elsif ordinal >= 0xC2 && ordinal <= 0xDF
          read_utf8_continuation(first, position, 1, reader)
        elsif ordinal >= 0xE0 && ordinal <= 0xEF
          read_utf8_continuation(first, position, 2, reader)
        elsif ordinal >= 0xF0 && ordinal <= 0xF4
          read_utf8_continuation(first, position, 3, reader)
        else
          error!("invalid UTF-8 byte", position)
        end
      end

      def read_utf8_continuation(first, position, length, reader)
        bytes = [first]
        length.times do
          next_position = @position
          if reader == :advance
            character = advance
            read_position = next_position
          else
            character, read_position = read_display_continuation_byte
          end
          if character.nil? || character.ord < 0x80 || character.ord > 0xBF
            error!("invalid UTF-8 continuation", read_position || next_position)
          end
          bytes << character
        end
        validate_utf8(bytes, position)
        bytes.each_with_index.map { |byte, index| [byte, position + index] }
      end

      def validate_utf8(bytes, position)
        values = bytes.map { |byte| byte.ord }
        codepoint = case values.length
        when 2
          ((values[0] & 0x1F) << 6) | (values[1] & 0x3F)
        when 3
          ((values[0] & 0x0F) << 12) | ((values[1] & 0x3F) << 6) | (values[2] & 0x3F)
        else
          ((values[0] & 0x07) << 18) | ((values[1] & 0x3F) << 12) |
            ((values[2] & 0x3F) << 6) | (values[3] & 0x3F)
        end

        minimum = { 2 => 0x80, 3 => 0x800, 4 => 0x10000 }.fetch(values.length)
        if codepoint < minimum || (0xD800..0xDFFF).include?(codepoint) || codepoint > 0x10FFFF
          error!("invalid UTF-8 sequence", position)
        end
      end

      def build_utf8(entries)
        output = String.new(encoding: Encoding::BINARY)
        entries.each { |byte, _position| output << byte }
        output.force_encoding(Encoding::UTF_8)
      end

      def read_display_continuation_byte
        if peek == "%"
          position = @position
          advance
          byte = read_percent_byte
          [byte, position]
        else
          position = @position
          [advance, position]
        end
      end

      def read_byte_sequence
        consume!(":")
        start = @position
        content = +""

        while peek && peek != ":"
          character = advance
          unless character.match?(/[A-Za-z0-9+\/=]/n)
            error!("invalid byte sequence", @position - 1)
          end
          content << character
        end
        error!("unterminated byte sequence", start - 1) unless consume(":")
        decode_base64(content, start)
      end

      def decode_base64(content, position)
        unless content.match?(BASE64_CHARS)
          error!("invalid base64 padding", position + content.index("="))
        end

        encoded = content + "=" * ((4 - content.length % 4) % 4)
        decoded = encoded.unpack1("m0")
        error!("invalid base64 encoding", position) if [decoded].pack("m0") != encoded
        ByteSequence.new(decoded)
      rescue ArgumentError
        error!("invalid base64 encoding", position)
      end

      def skip_spaces
        advance while peek == " "
      end

      def skip_ows
        while (character = peek) == " " || character == "\t"
          advance
        end
      end

      def consume(expected)
        return false unless peek == expected

        advance
        true
      end

      def consume!(expected, position = @position)
        error!("expected #{expected.inspect}", position) unless consume(expected)
      end

      def peek
        return nil if at_end?

        @field.getbyte(@position).chr(Encoding::BINARY)
      end

      def advance
        return nil if at_end?

        byte = @field.getbyte(@position)
        @position += 1
        byte.chr(Encoding::BINARY)
      end

      def slice(start, stop)
        @field.byteslice(start, stop - start)
      end

      def at_end?
        @position >= @field.bytesize
      end

      def error!(message, position = @position)
        raise ParseError.new(message, position)
      end

      def reject_duplicate_parameters(first, second, position)
        second.each_key do |key|
          error!("duplicate parameter key", position) if first.key?(key)
        end
      end
    end

    class Serializer
      INTEGER_MIN = -999_999_999_999_999
      INTEGER_MAX = 999_999_999_999_999
      KEY_CHARS = /\A[a-z*][a-z0-9_\-.*]*\z/n
      TOKEN_CHARS = %r{\A[A-Za-z*][A-Za-z0-9.!#$%&'*+\^_`|~:/\-]*\z}n

      def serialize_item(item)
        raise StructuredFieldError, "expected an Item" unless item.is_a?(Item)

        serialize_bare_value(item.value) + serialize_parameters(item.parameters)
      end

      def serialize_list(list)
        list.map { |member| serialize_member(member) }.join(", ")
      end

      def serialize_dictionary(dictionary)
        pairs = dictionary_pairs(dictionary)
        seen = {}

        pairs.map do |key, member|
          key = normalize_key(key)
          raise StructuredFieldError, "duplicate dictionary key: #{key}" if seen.key?(key)
          seen[key] = true
          serialize_dictionary_member(key, member)
        end.join(", ")
      end

      def serialize_member(member)
        case member
        when InnerList
          serialize_inner_list(member)
        when Item
          serialize_item(member)
        when Array
          serialize_inner_list(InnerList.new(member))
        else
          serialize_bare_value(member)
        end
      end

      def serialize_inner_list(inner_list)
        raise StructuredFieldError, "expected an InnerList" unless inner_list.is_a?(InnerList)

        members = inner_list.items.map do |item|
          item = Item.new(item) unless item.is_a?(Item)
          serialize_item(item)
        end
        "(" + members.join(" ") + ")" + serialize_parameters(inner_list.parameters)
      end

      def serialize_parameters(parameters)
        raise StructuredFieldError, "expected a Hash" unless parameters.is_a?(Hash)

        parameters.each_with_object(+"") do |(key, value), output|
          output << ";" << normalize_key(key)
          next if value == true

          output << "="
          case value
          when Item, InnerList, Array, Hash
            raise StructuredFieldError, "unsupported parameter value"
          else
            output << serialize_bare_value(value)
          end
        end
      end

      def serialize_bare_value(value)
        case value
        when Item, InnerList, Array, Hash
          raise StructuredFieldError, "expected a bare item"
        when true
          "?1"
        when false
          "?0"
        when Integer
          unless value.between?(INTEGER_MIN, INTEGER_MAX)
            raise StructuredFieldError, "integer out of range"
          end
          value.to_s
        when Decimal
          serialize_decimal(value)
        when Float
          if value.infinite? || value.nan?
            raise StructuredFieldError, "decimal out of range"
          end
          serialize_decimal(decimal_from_float(value))
        when SFDate
          unless value.value.is_a?(Integer) && value.value.between?(INTEGER_MIN, INTEGER_MAX)
            raise StructuredFieldError, "date out of range"
          end
          "@#{value.value}"
        when Token
          token = value.value.to_s.dup.force_encoding(Encoding::BINARY)
          unless token.match?(TOKEN_CHARS)
            raise StructuredFieldError, "invalid token"
          end
          token.force_encoding(Encoding::UTF_8)
        when ByteSequence
          bytes = binary_string(value.value)
          ":" + [bytes].pack("m0") + ":"
        when DisplayString
          serialize_display_string(value.value)
        when String
          serialize_string(value)
        when Symbol
          token = value.to_s.dup.force_encoding(Encoding::BINARY)
          unless token.match?(TOKEN_CHARS)
            raise StructuredFieldError, "invalid token"
          end
          token.force_encoding(Encoding::UTF_8)
        else
          raise StructuredFieldError, "unsupported value type: #{value.class}"
        end
      end

      def serialize_decimal(decimal)
        text = decimal.to_s
        integer_part, _fractional_part = text.split(".", 2)
        if integer_part.delete_prefix("-").length > 12
          raise StructuredFieldError, "decimal out of range"
        end
        if decimal.scale > 3
          raise StructuredFieldError, "decimal out of range"
        end
        decimal.scale.zero? ? "#{text}.0" : text
      end

      def decimal_from_float(value)
        text = format("%.15g", value)
        if text.include?("e")
          raise StructuredFieldError, "decimal out of range"
        end

        Decimal.new(text)
      rescue ArgumentError
        raise StructuredFieldError, "decimal out of range"
      end

      def serialize_string(value)
        text = value.to_s.dup
        unless text.encoding == Encoding::UTF_8 && text.valid_encoding?
          raise StructuredFieldError, "string must be valid UTF-8"
        end

        text.each_codepoint do |codepoint|
          if codepoint < 0x20 || codepoint == 0x7F
            raise StructuredFieldError, "invalid string control character"
          end
        end

        text.gsub!(/[\\"]/u) { |character| "\\#{character}" }
        '"' + text + '"'
      end

      def serialize_display_string(value)
        text = value.to_s.dup
        unless text.encoding == Encoding::UTF_8 && text.valid_encoding?
          raise StructuredFieldError, "display string must be valid UTF-8"
        end

        output = String.new('%"', encoding: Encoding::UTF_8)
        text.each_byte do |byte|
          if byte >= 0x21 && byte <= 0x7E && byte != 0x25 && byte != 0x22
            output << byte
          else
            output << format("%%%02X", byte)
          end
        end
        output << '"%'
      end

      def dictionary_pairs(dictionary)
        case dictionary
        when Hash
          dictionary.to_a
        when Array
          unless dictionary.all? { |pair| pair.is_a?(Array) && pair.length == 2 }
            raise StructuredFieldError, "expected key/value pairs"
          end
          dictionary
        else
          raise StructuredFieldError, "expected a Hash"
        end
      end

      def serialize_dictionary_member(key, member)
        output = +key

        case member
        when Item
          output << "=" << serialize_bare_value(member.value)
          output << serialize_parameters(member.parameters)
          return output
        when InnerList
          output << "=" << serialize_inner_list(member)
        when Array
          output << "=" << serialize_inner_list(InnerList.new(member))
        when Hash
          raise StructuredFieldError, "unsupported dictionary value"
        else
          return output if member == true

          output << "=" << serialize_bare_value(member)
        end
      end

      def normalize_key(key)
        normalized = key.to_s.dup.force_encoding(Encoding::BINARY)
        unless normalized.match?(KEY_CHARS)
          raise StructuredFieldError, "invalid structured field key"
        end
        normalized.force_encoding(Encoding::UTF_8)
      end

      def binary_string(value)
        bytes = value.to_s.dup
        bytes.force_encoding(Encoding::BINARY) unless bytes.encoding == Encoding::BINARY
        bytes
      end
    end
  end
end
