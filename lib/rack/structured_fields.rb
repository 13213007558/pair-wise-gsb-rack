# frozen_string_literal: true

require 'base64'
require 'bigdecimal'

module Rack
  # RFC 8941 Structured Fields parser and serializer.
  #
  # Unlike the helpers used for legacy comma- or semicolon-delimited HTTP
  # fields, these methods require the caller to name the field's top-level
  # type. Numeric values, tokens, strings and byte sequences are represented
  # by distinct Ruby types.
  module StructuredFields
    class ParseError < ArgumentError; end
    class SerializationError < ArgumentError; end

    MAX_INTEGER = 999_999_999_999_999
    MIN_INTEGER = -MAX_INTEGER
    MAX_DECIMAL = BigDecimal('999999999999.999')
    MIN_DECIMAL = -MAX_DECIMAL

    KEY = /\A[a-z*][a-z0-9_.*-]*\z/.freeze
    TOKEN_START = /[a-zA-Z*]/.freeze
    TOKEN_CHAR = /[A-Za-z0-9_.:\/%*!#$&'^`|~+-]/.freeze
    TOKEN = /\A[a-zA-Z*][A-Za-z0-9_.:\/%*!#$&'^`|~+-]*\z/.freeze
    NUMERIC_START = /[-0-9]/.freeze
    BASE64 = /\A[A-Za-z0-9+\/]*\z/.freeze
    private_constant :KEY, :TOKEN_START, :TOKEN_CHAR, :TOKEN, :NUMERIC_START, :BASE64

    class Decimal
      include Comparable

      attr_reader :value

      def initialize(value)
        unless value.is_a?(BigDecimal)
          raise ArgumentError, "#{self.class} requires a BigDecimal"
        end

        @value = value
        unless @value.finite?
          raise ArgumentError, "#{self.class} requires a finite decimal"
        end
        freeze
      end

      def self.parse(string)
        new(BigDecimal(string))
      end

      def <=>(other)
        case other
        when Decimal
          value <=> other.value
        when BigDecimal, Integer
          value <=> other
        end
      end

      def ==(other)
        other.is_a?(Decimal) && value == other.value
      end
      alias eql? ==

      def hash
        [self.class, value].hash
      end

      def to_s
        value.to_s('F')
      end

      def inspect
        "#<#{self.class}: #{self}>"
      end
    end

    class Token
      attr_reader :value

      def initialize(value)
        @value = String.new(value.to_str).freeze
        freeze
      end

      def ==(other)
        other.is_a?(Token) && value == other.value
      end
      alias eql? ==

      def hash
        [self.class, value].hash
      end

      def to_s
        value.dup
      end

      def inspect
        value.inspect
      end
    end

    class ByteSequence
      attr_reader :value

      def initialize(value)
        @value = String.new(value.to_str).force_encoding(Encoding::BINARY).freeze
        freeze
      end

      def self.decode(encoded)
        new(Base64.strict_decode64(encoded))
      end

      def encode
        Base64.strict_encode64(value)
      end

      def ==(other)
        other.is_a?(ByteSequence) && value == other.value
      end
      alias eql? ==

      def hash
        [self.class, value].hash
      end

      def to_s
        value.dup
      end

      def inspect
        value.inspect
      end
    end

    class Parameters
      include Enumerable

      def initialize(values = nil)
        @entries = []
        insert_all(values)
        freeze
      end

      def [](key)
        pair = @entries.reverse.find { |entry| entry[0] == key.to_s }
        pair && pair[1]
      end

      def each(&block)
        return to_enum(__method__) unless block
        @entries.each(&block)
        self
      end

      def to_a
        @entries.map(&:dup)
      end

      def to_h
        @entries.to_h
      end

      def ==(other)
        other.is_a?(Parameters) && to_a == other.to_a
      end
      alias eql? ==

      def hash
        [self.class, to_a].hash
      end

      private

      def insert_all(values)
        case values
        when nil
        when Hash
          values.each { |key, value| add(key, value) }
        when Array
          values.each do |entry|
            unless entry.is_a?(Array) && entry.length == 2
              raise ArgumentError, "invalid Structured Fields parameters entry"
            end
            add(entry[0], entry[1])
          end
        else
          raise ArgumentError, "invalid Structured Fields parameters"
        end
      end

      def add(key, value)
        raise ArgumentError, "frozen Structured Fields parameters" if frozen?
        key = key.to_s
        key.match?(KEY) or
          raise ArgumentError, "invalid Structured Fields parameter key: #{key.inspect}"

        value = value.dup.freeze if value.is_a?(String) && !value.frozen?
        index = @entries.rindex { |entry| entry[0] == key }
        if index
          @entries[index] = [key, value]
        else
          @entries << [key, value]
        end
      end
    end

    class Item
      attr_reader :value, :parameters

      def initialize(value, parameters = nil)
        @value = value.is_a?(String) && !value.frozen? ? value.dup.freeze : value
        @parameters = parameters.is_a?(Parameters) ? parameters : Parameters.new(parameters)
        freeze
      end

      def ==(other)
        other.is_a?(Item) &&
          value == other.value &&
          parameters == other.parameters
      end
      alias eql? ==

      def hash
        [self.class, value, parameters].hash
      end

      def deconstruct
        [value, parameters]
      end

      def inspect
        "#<#{self.class}: #{value.inspect} #{parameters.inspect}>"
      end
    end

    class InnerList
      include Enumerable

      attr_reader :parameters

      def initialize(values = [], parameters = nil)
        @values = values.to_a
        @parameters = parameters.is_a?(Parameters) ? parameters : Parameters.new(parameters)
        freeze
      end

      def each(&block)
        return to_enum(__method__) unless block
        @values.each(&block)
        self
      end

      def to_a
        @values.dup
      end

      def ==(other)
        other.is_a?(InnerList) &&
          to_a == other.to_a &&
          parameters == other.parameters
      end
      alias eql? ==

      def hash
        [self.class, to_a, parameters].hash
      end
    end

    class Dictionary
      include Enumerable

      def initialize(values = nil)
        @entries = []
        insert_all(values)
        freeze
      end

      def [](key)
        pair = @entries.find { |entry| entry[0] == key.to_s }
        pair && pair[1]
      end

      def each(&block)
        return to_enum(__method__) unless block
        @entries.each(&block)
        self
      end

      def to_a
        @entries.map(&:dup)
      end

      def to_h
        @entries.to_h
      end

      def ==(other)
        other.is_a?(Dictionary) && to_a == other.to_a
      end
      alias eql? ==

      def hash
        [self.class, to_a].hash
      end

      private

      def insert_all(values)
        case values
        when nil
        when Hash
          values.each { |key, value| add(key, value) }
        when Array
          values.each do |entry|
            unless entry.is_a?(Array) && entry.length == 2
              raise ArgumentError, "invalid Structured Fields dictionary entry"
            end
            add(entry[0], entry[1])
          end
        else
          raise ArgumentError, "invalid Structured Fields dictionary"
        end
      end

      def add(key, value)
        raise ArgumentError, "frozen Structured Fields dictionary" if frozen?
        key = begin
          key.to_str
        rescue
          key.to_s
        end
        key.match?(KEY) or
          raise ArgumentError, "invalid Structured Fields dictionary key: #{key.inspect}"

        index = @entries.rindex { |entry| entry[0] == key }
        if index
          @entries[index] = [key, value]
        else
          @entries << [key, value]
        end
      end
    end

    class Serializer
      def item(value)
        append_item(coerce_item(value))
      end

      def list(values)
        members = Array(values)
        members.map! { |value| list_member(value) }
        members.join(', ')
      end

      def dictionary(values)
        entries = dictionary_entries(values)
        entries.map { |key, value| dictionary_member(key, value) }.join(', ')
      end

      private

      def list_member(value)
        case value
        when InnerList
          append_inner_list(value)
        else
          append_item(coerce_item(value))
        end
      end

      def dictionary_entries(values)
        case values
        when Dictionary
          values.to_a
        when Hash, Array
          begin
            Dictionary.new(values).to_a
          rescue ArgumentError
            raise SerializationError, "invalid Structured Fields dictionary"
          end
        else
          raise SerializationError, "invalid Structured Fields dictionary"
        end
      end

      def dictionary_member(key, value)
        key = key.to_s
        key.match?(KEY) or
          raise SerializationError, "invalid Structured Fields dictionary key: #{key.inspect}"

        item = value.equal?(true) ? Item.new(true) : value
        if item.is_a?(Item) && item.value == true
          key + append_parameters(item.parameters)
        else
          "#{key}=#{list_member(item)}"
        end
      end

      def coerce_item(value)
        value.is_a?(Item) ? value : Item.new(value)
      end

      def append_item(item)
        raise SerializationError, "expected a Structured Fields item" unless item.is_a?(Item)
        append_bare_item(item.value) + append_parameters(item.parameters)
      end

      def append_inner_list(inner_list)
        raise SerializationError, "expected a Structured Fields inner list" unless inner_list.is_a?(InnerList)
        members = inner_list.map { |item| append_item(coerce_item(item)) }
        "(#{members.join(' ')})" + append_parameters(inner_list.parameters)
      end

      def append_parameters(parameters)
        raise SerializationError, "invalid Structured Fields parameters" unless parameters.is_a?(Parameters)
        parameters.map do |key, value|
          text = "; #{key}"
          unless value.equal?(true)
            text << "="
            text << append_bare_item(value)
          end
          text
        end.join
      end

      def append_bare_item(value)
        case value
        when Token
          append_token(value)
        when ByteSequence
          append_byte_sequence(value)
        when String
          append_string(value)
        when Decimal
          append_decimal(value)
        when Integer
          append_integer(value)
        when true
          '?1'
        when false
          "?#{value ? 1 : 0}"
        when Float, BigDecimal
          raise SerializationError, "use #{Decimal} for decimal values"
        else
          raise SerializationError, "unsupported Structured Fields value: #{value.class}"
        end
      end

      def append_integer(value)
        if value < MIN_INTEGER || value > MAX_INTEGER
          raise SerializationError, "integer out of range"
        end
        value.to_s
      end

      def append_decimal(value)
        decimal = value.value
        if decimal < MIN_DECIMAL || decimal > MAX_DECIMAL
          raise SerializationError, "decimal out of range"
        end
        unless decimal_scale(decimal) <= 3
          raise SerializationError, "decimal precision out of range"
        end
        value.to_s
      end

      def decimal_scale(decimal)
        _sign, digits, _base, exponent = decimal.split
        [digits.length - exponent, 0].max
      end

      def append_token(value)
        token = value.to_s
        token.match?(TOKEN) or
          raise SerializationError, "invalid Structured Fields token: #{token.inspect}"
        token.dup.force_encoding(Encoding::BINARY)
      end

      def append_string(value)
        string = value.to_s
        string.each_byte do |byte|
          unless byte == 0x09 || byte == 0x20 || (0x21..0x7e).cover?(byte)
            raise SerializationError, "invalid Structured Fields string character"
          end
        end
        escaped = string.gsub(/[\\"]/) { |character| "\\#{character}" }
        "\"#{escaped}\""
      end

      def append_byte_sequence(value)
        encoded = Base64.strict_encode64(value.value)
        encoded.delete_suffix!('=') while encoded.end_with?('=')
        ":#{encoded}:"
      end
    end

    class Parser
      def initialize(field)
        @input = field.to_s.dup.force_encoding(Encoding::BINARY)
        @index = 0
      end

      def item
        value = bare_item
        Item.new(value, parameters)
      end

      def list
        values = []
        return values if @input.empty?

        values << list_member
        skip_ows
        while consume(',')
          skip_ows
          values << list_member
        end
        values
      end

      def dictionary
        entries = []
        return Dictionary.new(entries) if @input.empty?

        entries << dictionary_member
        skip_ows
        while consume(',')
          skip_ows
          entries << dictionary_member
        end
        Dictionary.new(entries)
      end

      def finish!
        skip_ows
        error!("unexpected trailing characters") unless at_end?
      end

      private

      def list_member
        peek == '(' ? inner_list : item
      end

      def dictionary_member
        member_key = key

        if consume('=')
          [member_key, list_member]
        else
          [member_key, Item.new(true, parameters)]
        end
      end

      def inner_list
        expect!('(')
        values = []
        consume(' ')

        unless peek == ')'
          values << item
          until peek == ')'
            consume_sp!
            break if peek == ')'
            values << item
          end
        end

        expect!(')')
        InnerList.new(values, parameters)
      end

      def parameters
        entries = []

        while consume(';')
          consume_sp!
          parameter_key = key
          value = consume('=') ? param_value : true
          index = entries.rindex { |entry| entry[0] == parameter_key }
          if index
            entries[index] = [parameter_key, value]
          else
            entries << [parameter_key, value]
          end
        end

        Parameters.new(entries)
      end

      def param_value
        peek == '?' ? boolean : bare_item
      end

      def bare_item
        character = peek
        error!("expected a bare item") if character.nil?

        case character
        when '"'
          string
        when ':'
          byte_sequence
        when '?'
          boolean
        when NUMERIC_START
          number
        when TOKEN_START
          token
        else
          error!("invalid bare item")
        end
      end

      def number
        start = @index
        cursor = @index
        cursor += 1 if character_at(cursor) == '-'

        integer_start = cursor
        cursor += 1 while digit?(character_at(cursor))
        integer_digits = cursor - integer_start
        error!("invalid number") if integer_digits.zero?

        if character_at(cursor) == '.'
          cursor += 1
          fraction_start = cursor
          cursor += 1 while digit?(character_at(cursor))
          fraction_digits = cursor - fraction_start
          error!("invalid decimal") if fraction_digits.zero? || fraction_digits > 3
          error!("decimal out of range") if integer_digits > 12
          value = Decimal.parse(@input.byteslice(start, cursor - start))
          check_decimal_range!(value)
          @index = cursor
          value
        else
          error!("integer out of range") if integer_digits > 15
          @index = cursor
          Integer(@input.byteslice(start, cursor - start), 10)
        end
      end

      def string
        expect!('"')
        value = String.new.force_encoding(Encoding::BINARY)

        until peek == '"'
          character = peek
          error!("unterminated string") if character.nil?
          byte = character.ord
          unless byte == 0x09 || byte == 0x20 || (0x21..0x7e).cover?(byte)
            error!("invalid string character")
          end

          if character == '\\'
            @index += 1
            escaped = peek
            error!("invalid string escape") unless escaped == '"' || escaped == '\\'
            value << escaped
          else
            value << character
          end
          @index += 1
        end

        expect!('"')
        value
      end

      def token
        start = @index
        error!("invalid token") unless TOKEN_START.match?(peek)
        @index += 1
        @index += 1 while TOKEN_CHAR.match?(peek)
        Token.new(@input.byteslice(start, @index - start))
      end

      def byte_sequence
        expect!(':')
        closing = @input.index(':', @index)
        error!("unterminated byte sequence") unless closing
        encoded = @input.byteslice(@index, closing - @index)
        padded = canonical_base64_padding(encoded)
        unless padded
          error!("invalid byte sequence")
        end
        @index = closing + 1
        ByteSequence.decode(padded)
      end

      def boolean
        expect!('?')
        character = peek
        result = case character
        when '0'
          false
        when '1'
          true
        else
          error!("invalid boolean")
        end
        @index += 1
        result
      end

      def key
        start = @index
        character = peek
        unless character && character.match?(/[a-z*]/)
          error!("invalid key")
        end
        @index += 1
        @index += 1 while peek&.match?(/[a-z0-9_.*-]/)
        @input.byteslice(start, @index - start)
      end

      def canonical_base64_padding(encoded)
        return false unless encoded.match?(BASE64)
        padded = case encoded.bytesize % 4
        when 0
          encoded
        when 2
          encoded + '=='
        when 3
          encoded + '='
        else
          return false
        end

        begin
          decoded = Base64.strict_decode64(padded)
        rescue ArgumentError
          return false
        end
        Base64.strict_encode64(decoded) == padded ? padded : false
      end

      def check_decimal_range!(value)
        return if value >= MIN_DECIMAL && value <= MAX_DECIMAL
        error!("decimal out of range")
      end

      def digit?(character)
        character && character >= '0' && character <= '9'
      end

      def character_at(index)
        @input[index]
      end

      def peek
        @input[@index]
      end

      def consume(expected)
        if @input[@index] == expected
          @index += 1
          true
        else
          false
        end
      end

      def expect!(expected)
        error!("expected #{expected.inspect}") unless consume(expected)
      end

      def consume_sp!
        error!("expected a space") unless consume(' ')
      end

      def skip_ows
        @index += 1 while peek == ' ' || peek == "\t"
      end

      def at_end?
        @index == @input.bytesize
      end

      def error!(message)
        raise ParseError, message
      end
    end

    class << self
      def parse_item(field)
        parser = Parser.new(field_lines(field))
        parser.item.tap { parser.finish! }
      end

      def parse_list(field)
        parser = Parser.new(field_lines(field))
        parser.list.tap { parser.finish! }
      end

      def parse_dictionary(field)
        parser = Parser.new(field_lines(field))
        parser.dictionary.tap { parser.finish! }
      end
      alias parse_dict parse_dictionary

      def serialize_item(value)
        Serializer.new.item(value)
      end

      def serialize_list(values)
        Serializer.new.list(values)
      end

      def serialize_dictionary(values)
        Serializer.new.dictionary(values)
      end
      alias serialize_dict serialize_dictionary

      private

      def field_lines(field)
        lines = case field
        when String
          [field]
        when Array
          field.map do |line|
            line.is_a?(String) or
              raise ParseError, "Structured Fields lines must be strings"
            line
          end
        else
          raise ParseError, "Structured Fields field must be a string or array"
        end
        lines.map! do |line|
          line.gsub(/\r\n[\t ]+/, ' ')
        end
        lines.join(',')
      end
    end
  end
end
