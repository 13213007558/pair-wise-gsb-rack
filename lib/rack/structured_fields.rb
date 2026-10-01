# frozen_string_literal: true

require_relative 'structured_fields/value_types'
require_relative 'structured_fields/parser'
require_relative 'structured_fields/serializer'

module Rack
  # RFC 9651 Structured Fields.
  module StructuredFields
    SHAPES = [:item, :list, :dictionary].freeze

    class ParseError < ArgumentError
      attr_reader :byte_position

      def initialize(message, byte_position = nil)
        @byte_position = byte_position

        if byte_position.nil?
          super(message)
        else
          super("#{message} at byte #{byte_position}")
        end
      end
    end

    class SerializationError < ArgumentError
    end

    def self.parse(shape, input)
      Parser.new(input).parse(shape)
    end

    def self.serialize(shape, value)
      Serializer.new.serialize(shape, value)
    end

    def self.parse_item(input)
      parse(:item, input)
    end

    def self.parse_list(input)
      parse(:list, input)
    end

    def self.parse_dictionary(input)
      parse(:dictionary, input)
    end

    def self.serialize_item(value)
      serialize(:item, value)
    end

    def self.serialize_list(value)
      serialize(:list, value)
    end

    def self.serialize_dictionary(value)
      serialize(:dictionary, value)
    end
  end
end
