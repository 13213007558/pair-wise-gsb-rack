# frozen_string_literal: true

require 'base64'

module Rack
  # Rack::StructuredFields parses and serializes RFC 8941 Structured
  # Field Values for HTTP.
  #
  # This is an explicitly invoked utility: the caller declares the
  # top-level type of the field (Item, List, or Dictionary) by choosing
  # the matching parse/serialize method.  Rack's regular string header
  # handling is not affected by it.
  #
  # Bare item values are represented with distinct Ruby types:
  #
  # * Integer       => Integer
  # * Decimal       => Rack::StructuredFields::Decimal
  # * String        => String
  # * Token         => Rack::StructuredFields::Token
  # * Byte Sequence => Rack::StructuredFields::ByteSequence
  # * Boolean       => true/false
  #
  # Compound values are represented by Rack::StructuredFields::Item (a
  # bare value plus parameters), Rack::StructuredFields::InnerList,
  # Rack::StructuredFields::Parameters, and
  # Rack::StructuredFields::Dictionary.
  #
  #   field = Rack::StructuredFields.parse_dictionary('a=1, b=?0;foo=bar')
  #   field['a'].value # => 1
  #   Rack::StructuredFields.serialize_dictionary(field)
  #   # => "a=1, b=?0;foo=bar"
  #
  # Parsing is strict: duplicate dictionary members and parameters,
  # out of range integers, overlong decimals, bad escapes, and trailing
  # garbage all raise Rack::StructuredFields::ParseError, and a failed
  # parse never yields a partial result.
  class StructuredFields
    # Base class for StructuredFields errors.
    class Error < StandardError; end

    # Raised when a field value cannot be parsed as the expected
    # top-level structured field type.
    class ParseError < Error; end

    # Raised when a Ruby object cannot be serialized as (part of) a
    # structured field, e.g. an out of range integer, a decimal with
    # more than three fractional digits, or an invalid token or key.
    class SerializationError < Error; end

    # The largest absolute value allowed for an Integer (15 digits).
    INTEGER_LIMIT = 999_999_999_999_999

    # The largest absolute value allowed for a Decimal (an integer
    # component of 12 digits plus 3 fractional digits).
    DECIMAL_LIMIT = Rational(999_999_999_999_999, 1000)

    KEY_PATTERN = /\A[a-z*][a-z0-9_.\-*]*\z/.freeze
    TOKEN_PATTERN = /\A[A-Za-z*][A-Za-z0-9!#$%&'*+\-.^_`|~:\/]*\z/.freeze

    class << self
      # Parse +field+ as an Item, returning a
      # Rack::StructuredFields::Item.  +field+ may be a String or an
      # Array of field lines (see #combine).
      def parse_item(field)
        parser = Parser.new(combine(field))
        parser.skip_ows
        item = parser.parse_item
        parser.finish!
        item
      end

      # Parse +field+ as a List, returning an Array of
      # Rack::StructuredFields::Item and
      # Rack::StructuredFields::InnerList members.
      def parse_list(field)
        parser = Parser.new(combine(field))
        parser.skip_ows
        list = parser.parse_list
        parser.finish!
        list
      end

      # Parse +field+ as a Dictionary, returning a
      # Rack::StructuredFields::Dictionary.
      def parse_dictionary(field)
        parser = Parser.new(combine(field))
        parser.skip_ows
        dictionary = parser.parse_dictionary
        parser.finish!
        dictionary
      end

      # Serialize +item+ (a Rack::StructuredFields::Item or a bare
      # value) as an Item field value.
      def serialize_item(item)
        item = Item.new(item) unless item.is_a?(Item)
        serialize_bare_item(item.value) + serialize_parameters(item.parameters)
      end

      # Serialize +list+ (an Array of items and inner lists) as a List
      # field value.
      def serialize_list(list)
        unless list.is_a?(Array)
          raise SerializationError, "a List must be serialized from an Array, got #{list.inspect}"
        end

        list.map do |member|
          member.is_a?(InnerList) ? serialize_inner_list(member) : serialize_item(member)
        end.join(", ")
      end

      # Serialize +dictionary+ (a Rack::StructuredFields::Dictionary, a
      # Hash, or an Array of key/value pairs) as a Dictionary field
      # value.
      def serialize_dictionary(dictionary)
        unless dictionary.is_a?(Dictionary) || dictionary.is_a?(Hash) || dictionary.is_a?(Array)
          raise SerializationError, "cannot serialize #{dictionary.inspect} as a Dictionary"
        end

        dictionary.map do |key, member|
          key = valid_key!(key)
          member = Item.new(member) unless member.is_a?(Item) || member.is_a?(InnerList)

          if member.is_a?(InnerList)
            "#{key}=#{serialize_inner_list(member)}"
          elsif member.value == true
            "#{key}#{serialize_parameters(member.parameters)}"
          else
            "#{key}=#{serialize_item(member)}"
          end
        end.join(", ")
      end

      # Combine received field lines into a single field value string
      # according to HTTP rules (RFC 9110, Section 5.2): obsolete line
      # folding is replaced by a single space, and separate field lines
      # are joined with ", ".  Accepts a String (possibly containing
      # CRLF-separated lines) or an Array of line Strings.  The whole
      # combined value is parsed afterwards, so a failure cannot leave
      # a partial result.
      def combine(field)
        case field
        when Array
          field.map do |line|
            line = String(line)
            if line.match?(/[\r\n]/)
              raise ParseError, "field line contains CR or LF"
            end
            line
          end.join(", ")
        when nil
          raise ParseError, "cannot parse nil as a structured field"
        else
          string = String(field).gsub("\r\n", "\n")
          if string.include?("\r")
            raise ParseError, "field value contains a bare CR"
          end
          # Replace obsolete line folding with a single space, then
          # combine any remaining separate field lines.
          string.gsub(/\n[ \t]+/, " ").split("\n").join(", ")
        end
      end

      # Validate +key+ as a Dictionary or Parameters key, returning it
      # as a String.  Raises SerializationError if invalid.
      def valid_key!(key)
        key = key.to_s if key.is_a?(Symbol)
        unless key.is_a?(String) && key.ascii_only? && KEY_PATTERN.match?(key)
          raise SerializationError, "invalid key: #{key.inspect}"
        end
        key
      end

      # Validate +token+ as a Token value.  Raises SerializationError
      # if invalid.
      def valid_token!(token)
        unless token.ascii_only? && TOKEN_PATTERN.match?(token)
          raise SerializationError, "invalid token: #{token.inspect}"
        end
        token
      end

      private

      def serialize_inner_list(inner_list)
        serialized = inner_list.items.map do |item|
          serialize_item(item)
        end.join(" ")
        "(#{serialized})#{serialize_parameters(inner_list.parameters)}"
      end

      def serialize_parameters(parameters)
        parameters.map do |key, value|
          key = valid_key!(key)
          if value == true
            ";#{key}"
          else
            ";#{key}=#{serialize_bare_item(value)}"
          end
        end.join
      end

      def serialize_bare_item(value)
        case value
        when Integer
          if value.abs > INTEGER_LIMIT
            raise SerializationError, "integer #{value} is outside the allowed range"
          end
          value.to_s
        when Decimal
          value.to_s
        when Token
          valid_token!(value)
        when ByteSequence
          ":#{Base64.strict_encode64(value.to_s)}:"
        when String
          serialize_string(value)
        when Symbol
          valid_token!(value.to_s)
        when true
          "?1"
        when false
          "?0"
        when Rational, Float
          Decimal.new(value).to_s
        else
          if defined?(BigDecimal) && value.is_a?(BigDecimal)
            Decimal.new(value).to_s
          else
            raise SerializationError, "cannot serialize #{value.inspect} as a bare item"
          end
        end
      end

      def serialize_string(value)
        unless value.ascii_only?
          raise SerializationError, "cannot serialize non-ASCII string: #{value.inspect}"
        end

        out = +'"'
        value.each_char do |char|
          byte = char.ord
          if byte < 0x20 || byte > 0x7e
            raise SerializationError, "string contains a non-printable character: #{value.inspect}"
          end
          out << "\\" if char == '"' || char == "\\"
          out << char
        end
        out << '"'
      end
    end

    # A Token value (RFC 8941, Section 3.3.4).  A String subclass
    # validated against the token ABNF on creation.
    class Token < String
      def initialize(value)
        value = value.to_s if value.is_a?(Symbol)
        value = String(value)
        StructuredFields.valid_token!(value)
        super(value)
      end
    end

    # A Byte Sequence value (RFC 8941, Section 3.3.5), wrapping the
    # decoded bytes as a binary String.
    class ByteSequence
      def initialize(bytes)
        @bytes = String(bytes).dup.force_encoding(Encoding::BINARY).freeze
      end

      # The decoded bytes, as a binary String.
      def to_s
        @bytes.dup
      end
      alias bytes to_s

      def size
        @bytes.size
      end
      alias length size

      def ==(other)
        case other
        when ByteSequence then @bytes == other.to_s
        when String then @bytes == other
        else false
        end
      end
      alias eql? ==

      def hash
        [self.class, @bytes].hash
      end

      def inspect
        "#<#{self.class.name} :#{Base64.strict_encode64(@bytes)}:>"
      end
    end

    # A Decimal value (RFC 8941, Section 3.3.2).  Decimals are exact:
    # at most three fractional digits, and an integer component of at
    # most twelve digits.  The value is stored as a Rational.
    class Decimal
      include Comparable

      # The exact value, as a Rational.
      attr_reader :value

      def initialize(value)
        rational =
          case value
          when Decimal
            value.value
          when Integer, Rational, Float
            value.to_r
          else
            if value.is_a?(String) || !value.respond_to?(:to_r)
              raise SerializationError, "cannot serialize #{value.inspect} as a decimal"
            end
            value.to_r
          end

        unless rational.is_a?(Rational)
          raise SerializationError, "cannot serialize #{value.inspect} as a decimal"
        end

        if (rational * 1000).denominator != 1
          raise SerializationError, "#{value.inspect} has more than 3 decimal places"
        end

        if rational.abs > DECIMAL_LIMIT
          raise SerializationError, "#{value.inspect} is outside the allowed decimal range"
        end

        @value = rational
      end

      def <=>(other)
        case other
        when Decimal then value <=> other.value
        when Numeric then value <=> other
        end
      end

      def eql?(other)
        other.is_a?(Decimal) && value == other.value
      end

      def hash
        [self.class, value].hash
      end

      def to_r
        value
      end

      def to_f
        value.to_f
      end

      def to_i
        value.to_i
      end

      # The canonical RFC 8941 serialization of the decimal.
      def to_s
        scaled = (value.abs * 1000).to_i
        int_part, frac_part = scaled.divmod(1000)
        fraction = format("%03d", frac_part).sub(/0+\z/, "")
        fraction = "0" if fraction.empty?
        "#{value.negative? ? '-' : ''}#{int_part}.#{fraction}"
      end

      def inspect
        "#<#{self.class.name} #{self}>"
      end
    end

    # An Item: a bare value plus an ordered set of parameters
    # (RFC 8941, Section 3.3).
    class Item
      attr_reader :value, :parameters

      def initialize(value, parameters = nil)
        @value = value
        @parameters = parameters.is_a?(Parameters) ? parameters : Parameters.new(parameters)
      end

      def ==(other)
        other.is_a?(Item) && value == other.value && parameters == other.parameters
      end
      alias eql? ==

      def hash
        [self.class, value, parameters].hash
      end

      def inspect
        "#<#{self.class.name} value=#{value.inspect} parameters=#{parameters.to_h.inspect}>"
      end
    end

    # An Inner List: an ordered list of items plus an ordered set of
    # parameters (RFC 8941, Section 3.1.1).
    class InnerList
      include Enumerable

      attr_reader :items, :parameters

      def initialize(items = [], parameters = nil)
        @items = items.map { |item| item.is_a?(Item) ? item : Item.new(item) }
        @parameters = parameters.is_a?(Parameters) ? parameters : Parameters.new(parameters)
      end

      def each(&block)
        items.each(&block)
      end

      def [](index)
        items[index]
      end

      def size
        items.size
      end
      alias length size

      def to_a
        items.dup
      end

      def ==(other)
        other.is_a?(InnerList) && items == other.items && parameters == other.parameters
      end
      alias eql? ==

      def hash
        [self.class, items, parameters].hash
      end

      def inspect
        "#<#{self.class.name} items=#{items.inspect} parameters=#{parameters.to_h.inspect}>"
      end
    end

    # An ordered set of parameters (RFC 8941, Section 3.1.2).  Keys are
    # validated; insertion order is preserved.
    class Parameters
      include Enumerable

      def initialize(entries = nil)
        @entries = {}
        return if entries.nil?
        entries.each do |key, value|
          self[key] = value
        end
      end

      def [](key)
        @entries[key]
      end

      def []=(key, value)
        @entries[StructuredFields.valid_key!(key)] = value
      end

      def key?(key)
        @entries.key?(key)
      end

      def each(&block)
        @entries.each(&block)
      end

      def keys
        @entries.keys
      end

      def size
        @entries.size
      end
      alias length size

      def empty?
        @entries.empty?
      end

      def to_h
        @entries.dup
      end

      def ==(other)
        case other
        when Parameters then @entries == other.to_h
        when Hash then @entries == other
        else false
        end
      end
      alias eql? ==

      def hash
        [self.class, @entries].hash
      end

      def inspect
        "#<#{self.class.name} #{@entries.inspect}>"
      end
    end

    # An ordered map of dictionary members (RFC 8941, Section 3.2).
    # Keys are validated; insertion order is preserved.  Values are
    # Rack::StructuredFields::Item or Rack::StructuredFields::InnerList
    # instances; bare values assigned by the user are wrapped in an
    # Item automatically.
    class Dictionary
      include Enumerable

      def initialize(entries = nil)
        @entries = {}
        return if entries.nil?
        entries.each do |key, value|
          self[key] = value
        end
      end

      def [](key)
        @entries[key]
      end

      def []=(key, value)
        key = StructuredFields.valid_key!(key)
        value = Item.new(value) unless value.is_a?(Item) || value.is_a?(InnerList)
        @entries[key] = value
      end

      def key?(key)
        @entries.key?(key)
      end

      def each(&block)
        @entries.each(&block)
      end

      def keys
        @entries.keys
      end

      def size
        @entries.size
      end
      alias length size

      def empty?
        @entries.empty?
      end

      def to_h
        @entries.dup
      end

      def ==(other)
        other.is_a?(Dictionary) && @entries == other.to_h
      end
      alias eql? ==

      def hash
        [self.class, @entries].hash
      end

      def inspect
        "#<#{self.class.name} #{@entries.inspect}>"
      end
    end

    # Recursive descent parser for RFC 8941 field values (Section
    # 4.2).  Internal: use the StructuredFields.parse_* methods.
    class Parser
      SP = 0x20
      HTAB = 0x09
      DQUOTE = 0x22
      BACKSLASH = 0x5C
      SEMICOLON = 0x3B
      COMMA = 0x2C
      EQUALS = 0x3D
      LPAREN = 0x28
      RPAREN = 0x29
      COLON = 0x3A
      MINUS = 0x2D
      PERIOD = 0x2E
      QUESTION = 0x3F
      STAR = 0x2A

      TCHAR = {}
      '!#$%&\'*+-.^_`|~'.each_byte { |byte| TCHAR[byte] = true }
      TCHAR.freeze

      def initialize(input)
        @input = input.b
        @pos = 0
        @length = @input.length
      end

      def eof?
        @pos >= @length
      end

      def peek
        @input.getbyte(@pos)
      end

      def advance
        @pos += 1
      end

      def error(message)
        raise ParseError, "#{message} (at index #{@pos})"
      end

      def expect(byte, message)
        error(message) unless peek == byte
        advance
      end

      def skip_ows
        advance while peek == SP || peek == HTAB
      end

      # Verify nothing but optional whitespace remains after a
      # top-level value.
      def finish!
        skip_ows
        error("unexpected trailing characters") unless eof?
      end

      def parse_item
        Item.new(parse_bare_item, parse_parameters)
      end

      def parse_list
        members = []
        until eof?
          members << parse_item_or_inner_list
          skip_ows
          break if eof?
          expect(COMMA, "expected ',' between list members")
          skip_ows
          error("trailing comma in list") if eof?
        end
        members
      end

      def parse_dictionary
        dictionary = Dictionary.new
        until eof?
          key = parse_key
          value =
            if peek == EQUALS
              advance
              parse_item_or_inner_list
            else
              Item.new(true, parse_parameters)
            end
          if dictionary.key?(key)
            error("duplicate dictionary member #{key.inspect}")
          end
          dictionary[key] = value
          skip_ows
          break if eof?
          expect(COMMA, "expected ',' between dictionary members")
          skip_ows
          error("trailing comma in dictionary") if eof?
        end
        dictionary
      end

      def parse_item_or_inner_list
        peek == LPAREN ? parse_inner_list : parse_item
      end

      def parse_inner_list
        advance # '('
        items = []
        loop do
          advance while peek == SP
          if peek == RPAREN
            advance
            break
          end
          items << parse_item
          unless peek == SP || peek == RPAREN
            error("expected a space or ')' in inner list")
          end
        end
        InnerList.new(items, parse_parameters)
      end

      def parse_parameters
        parameters = Parameters.new
        while peek == SEMICOLON
          advance
          advance while peek == SP
          key = parse_key
          value =
            if peek == EQUALS
              advance
              parse_bare_item
            else
              true
            end
          if parameters.key?(key)
            error("duplicate parameter #{key.inspect}")
          end
          parameters[key] = value
        end
        parameters
      end

      def parse_key
        unless lowercase?(peek) || peek == STAR
          error("expected a key")
        end
        start = @pos
        advance
        advance while key_char?(peek)
        @input.byteslice(start, @pos - start).force_encoding(Encoding::UTF_8)
      end

      def parse_bare_item
        byte = peek
        if byte == MINUS || digit?(byte)
          parse_number
        elsif byte == DQUOTE
          parse_string
        elsif alpha?(byte) || byte == STAR
          parse_token
        elsif byte == COLON
          parse_byte_sequence
        elsif byte == QUESTION
          parse_boolean
        else
          error("expected a bare item")
        end
      end

      def parse_number
        sign = 1
        if peek == MINUS
          advance
          sign = -1
        end
        error("expected a digit") unless digit?(peek)

        int_start = @pos
        advance while digit?(peek)
        int_digits = @pos - int_start

        if peek == PERIOD
          if int_digits > 12
            error("too many digits before the decimal point")
          end
          advance
          frac_start = @pos
          advance while digit?(peek)
          frac_digits = @pos - frac_start
          if frac_digits == 0
            error("decimal point must be followed by at least one digit")
          end
          if frac_digits > 3
            error("too many digits after the decimal point")
          end
          int_part = @input.byteslice(int_start, int_digits).to_i
          frac_part = @input.byteslice(frac_start, frac_digits).to_i
          scaled = int_part * 1000 + frac_part * (10**(3 - frac_digits))
          Decimal.new(Rational(sign * scaled, 1000))
        else
          if int_digits > 15
            error("too many digits in integer")
          end
          value = sign * @input.byteslice(int_start, int_digits).to_i
          if value.abs > INTEGER_LIMIT
            error("integer is outside the allowed range")
          end
          value
        end
      end

      def parse_string
        advance # '"'
        out = +""
        until eof?
          byte = @input.getbyte(@pos)
          advance
          case byte
          when DQUOTE
            return out.force_encoding(Encoding::UTF_8)
          when BACKSLASH
            error("unterminated escape in string") if eof?
            escaped = @input.getbyte(@pos)
            advance
            unless escaped == DQUOTE || escaped == BACKSLASH
              error("invalid escape in string")
            end
            out << escaped
          else
            if byte < 0x20 || byte > 0x7E
              error("invalid character in string")
            end
            out << byte
          end
        end
        error("unterminated string")
      end

      def parse_token
        start = @pos
        advance
        advance while tchar?(peek)
        Token.new(@input.byteslice(start, @pos - start))
      end

      def parse_byte_sequence
        advance # ':'
        start = @pos
        until eof?
          byte = peek
          break if byte == COLON
          unless base64_char?(byte)
            error("invalid character in byte sequence")
          end
          advance
        end
        error("unterminated byte sequence") if eof?
        content = @input.byteslice(start, @pos - start)
        advance # ':'
        ByteSequence.new(Base64.decode64(content))
      end

      def parse_boolean
        advance # '?'
        byte = peek
        if byte == 0x31 # '1'
          advance
          true
        elsif byte == 0x30 # '0'
          advance
          false
        else
          error("invalid boolean")
        end
      end

      private

      def digit?(byte)
        !byte.nil? && byte >= 0x30 && byte <= 0x39
      end

      def alpha?(byte)
        !byte.nil? && ((byte >= 0x41 && byte <= 0x5A) || (byte >= 0x61 && byte <= 0x7A))
      end

      def lowercase?(byte)
        !byte.nil? && byte >= 0x61 && byte <= 0x7A
      end

      def key_char?(byte)
        lowercase?(byte) || digit?(byte) ||
          byte == 0x5F || byte == 0x2D || byte == 0x2E || byte == STAR
      end

      def tchar?(byte)
        alpha?(byte) || digit?(byte) || byte == COLON || byte == 0x2F ||
          TCHAR.key?(byte)
      end

      def base64_char?(byte)
        alpha?(byte) || digit?(byte) ||
          byte == 0x2B || byte == 0x2F || byte == EQUALS
      end
    end
  end
end
