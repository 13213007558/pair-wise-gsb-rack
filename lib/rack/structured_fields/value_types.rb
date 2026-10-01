# frozen_string_literal: true

module Rack
  module StructuredFields
    class Token < String
      def initialize(value)
        super(String(value).dup.freeze)
        freeze
      end
    end

    class ByteSequence < String
      def initialize(value)
        super(String(value).b.dup.freeze)
        freeze
      end
    end

    class DisplayString < String
      def initialize(value)
        text = String(value).dup
        text.force_encoding(Encoding::UTF_8)
        unless text.valid_encoding?
          raise ArgumentError, "invalid UTF-8 in display string"
        end

        super(text.freeze)
        freeze
      end
    end

    class Date
      attr_reader :value

      def initialize(value)
        unless value.is_a?(Integer)
          raise ArgumentError, "Structured Field date must be an Integer"
        end

        @value = value
        freeze
      end

      def to_i
        @value
      end

      def ==(other)
        other.is_a?(Date) && other.value == @value
      end
      alias eql? ==

      def hash
        [self.class, @value].hash
      end

      def inspect
        "#<Rack::StructuredFields::Date #{@value}>"
      end
    end

    class Item
      attr_reader :value, :parameters

      def initialize(value, parameters = {})
        @value = value
        @parameters = normalize_parameters(parameters)
        freeze
      end

      def ==(other)
        other.is_a?(Item) &&
          other.value == @value &&
          other.parameters == @parameters
      end
      alias eql? ==

      def hash
        [self.class, @value, @parameters].hash
      end

      def inspect
        "#<Rack::StructuredFields::Item #{@value.inspect} #{@parameters.inspect}>"
      end

      private

      def normalize_parameters(parameters)
        unless parameters.is_a?(Hash)
          raise ArgumentError, "Structured Field parameters must be a Hash"
        end

        parameters.each do |key, value|
          unless key.is_a?(String) && key.match?(/\A[a-z*][a-z0-9*_.\-]*\z/)
            raise ArgumentError, "invalid Structured Field parameter key #{key.inspect}"
          end

          if value.is_a?(Item) || value.is_a?(InnerList)
            raise ArgumentError, "parameter values cannot be structured members"
          end
        end

        parameters.dup.freeze
      end
    end

    class InnerList
      attr_reader :entries, :parameters

      def initialize(entries = [], parameters = {})
        unless entries.is_a?(Array)
          raise ArgumentError, "Structured Field inner list entries must be an Array"
        end

        @entries = entries.dup.freeze
        @parameters = Item.new(true, parameters).parameters
        freeze
      end

      def ==(other)
        other.is_a?(InnerList) &&
          other.entries == @entries &&
          other.parameters == @parameters
      end
      alias eql? ==

      def hash
        [self.class, @entries, @parameters].hash
      end

      def inspect
        "#<Rack::StructuredFields::InnerList #{@entries.inspect} #{@parameters.inspect}>"
      end
    end
  end
end
