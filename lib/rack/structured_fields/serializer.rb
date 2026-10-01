# frozen_string_literal: true

module Rack
  module StructuredFields
    class Serializer
      INTEGER_MIN = -999_999_999_999_999
      INTEGER_MAX = 999_999_999_999_999
      DECIMAL_INTEGER_MAX = 12
      TOKEN_EXTRA_BYTES = "!#$%&'*+-.".bytes.freeze
      TOKEN_SYMBOL_BYTES = '^_|~:/'.bytes.freeze

      def serialize(shape, value)
        output = String.new.b

        case shape
        when :item
          serialize_member(output, value)
        when :list
          unless value.is_a?(Array)
            raise SerializationError, "Structured Field list must be an Array"
          end

          value.each_with_index do |entry, index|
            output << ', ' unless index.zero?
            serialize_member(output, entry)
          end
        when :dictionary
          unless value.is_a?(Hash)
            raise SerializationError, "Structured Field dictionary must be a Hash"
          end

          value.each_with_index do |(key, entry), index|
            output << ', ' unless index.zero?
            serialize_dictionary_entry(output, key, entry)
          end
        else
          raise ArgumentError, "unknown Structured Field shape #{shape.inspect}"
        end

        output
      end

      private

      def serialize_member(output, value)
        case value
        when InnerList
          serialize_inner_list(output, value)
        when Item
          serialize_item(output, value)
        else
          raise SerializationError, "expected Structured Field Item or InnerList"
        end
      end

      def serialize_dictionary_entry(output, key, value)
        output << valid_key(key)

        case value
        when true
          # Bare true is represented by the key alone.
        when Item
          unless value.value == true
            output << '='
            serialize_bare_item(output, value.value)
          end
          serialize_parameters(output, value.parameters)
        when InnerList
          output << '='
          serialize_inner_list(output, value)
        else
          output << '='
          serialize_bare_item(output, value)
        end
      end

      def serialize_item(output, item)
        serialize_bare_item(output, item.value)
        serialize_parameters(output, item.parameters)
      end

      def serialize_inner_list(output, inner_list)
        output << '('

        inner_list.entries.each_with_index do |entry, index|
          output << ' ' unless index.zero?

          unless entry.is_a?(Item)
            raise SerializationError, "inner list entries must be Items"
          end

          serialize_item(output, entry)
        end

        output << ')'
        serialize_parameters(output, inner_list.parameters)
      end

      def serialize_parameters(output, parameters)
        unless parameters.is_a?(Hash)
          raise SerializationError, "Structured Field parameters must be a Hash"
        end

        parameters.each do |key, value|
          output << ' ; ' << valid_key(key)

          unless value == true
            if value.is_a?(Item) || value.is_a?(InnerList)
              raise SerializationError, "parameter values cannot be structured members"
            end

            output << '='
            serialize_bare_item(output, value)
          end
        end
      end

      def serialize_bare_item(output, value)
        case value
        when Item, InnerList
          raise SerializationError, "unexpected structured member in bare item position"
        when Token
          output << valid_token(value)
        when ByteSequence
          output << ':' << [String(value)].pack('m0') << ':'
        when DisplayString
          serialize_display_string(output, value)
        when Date
          output << '@' << valid_integer(value.value).to_s
        when true, false
          output << (value ? '?1' : '?0')
        when String
          serialize_string(output, value)
        when Integer
          output << valid_integer(value).to_s
        when Float
          output << valid_decimal(value)
        when nil
          raise SerializationError, "nil is not a Structured Field value"
        else
          raise SerializationError, "unsupported Structured Field value #{value.class}"
        end
      end

      def serialize_string(output, value)
        output << '"'

        value.each_codepoint do |codepoint|
          if codepoint == '"'.ord || codepoint == '\\'.ord
            output << '\\' << codepoint
          elsif codepoint >= 0x20 && codepoint <= 0x7E
            output << codepoint
          else
            raise SerializationError, "Structured Field strings may contain only printable ASCII"
          end
        end

        output << '"'
      rescue ArgumentError
        raise SerializationError, "invalid UTF-8 in Structured Field string"
      end

      def serialize_display_string(output, value)
        output << '%"'

        value.each_codepoint do |codepoint|
          if display_raw_ascii?(codepoint)
            output << codepoint
          elsif codepoint >= 0x20 && codepoint <= 0x7E
            append_percent_encoded(output, codepoint.chr.b)
          elsif codepoint >= 0x80 && codepoint <= 0x10FFFF
            append_percent_encoded(output, [codepoint].pack('U'))
          else
            raise SerializationError, "invalid display string character"
          end
        end

        output << '"'
      rescue ArgumentError
        raise SerializationError, "invalid UTF-8 in Structured Field display string"
      end

      def append_percent_encoded(output, bytes)
        bytes.each_byte do |byte|
          output << '%' << format('%02X', byte)
        end
      end

      def display_raw_ascii?(codepoint)
        codepoint == ' '.ord ||
          (codepoint >= '!'.ord && codepoint <= '~'.ord &&
            codepoint != '"'.ord && codepoint != '%'.ord)
      end

      def valid_integer(value)
        unless value >= INTEGER_MIN && value <= INTEGER_MAX
          raise SerializationError, "integer is out of Structured Field range"
        end

        value
      end

      def valid_decimal(value)
        unless value.finite?
          raise SerializationError, "decimal must be finite"
        end

        value = 0.0 if value.zero?
        text = value.to_s

        if text.include?('e') || text.include?('E')
          raise SerializationError, "decimal cannot be serialized in scientific notation"
        end

        integer_part, fraction_part = text.split('.', 2)
        integer_part = integer_part.sub(/\A-/, '')

        if integer_part.length > DECIMAL_INTEGER_MAX || fraction_part.length > 3
          raise SerializationError, "decimal is out of Structured Field range or precision"
        end

        text
      end

      def valid_key(key)
        unless key.is_a?(String) &&
               key.encoding == Encoding::UTF_8 &&
               key.match?(/\A[a-z*][a-z0-9*_.\-]*\z/)
          raise SerializationError, "invalid Structured Field key #{key.inspect}"
        end

        key
      end

      def valid_token(value)
        bytes = String(value).b
        first = bytes.getbyte(0)

        unless token_start?(first) && bytes.each_byte.all? { |byte| token_byte?(byte) }
          raise SerializationError, "invalid Structured Field token #{value.inspect}"
        end

        bytes
      end

      def token_start?(byte)
        return false if byte.nil?

        (byte >= 'A'.ord && byte <= 'Z'.ord) ||
          (byte >= 'a'.ord && byte <= 'z'.ord) ||
          byte == '*'.ord
      end

      def token_byte?(byte)
        token_start?(byte) ||
          (byte >= '0'.ord && byte <= '9'.ord) ||
          TOKEN_EXTRA_BYTES.include?(byte) || byte == 0x60 || TOKEN_SYMBOL_BYTES.include?(byte)
      end
    end
  end
end
