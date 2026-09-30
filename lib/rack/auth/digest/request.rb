# frozen_string_literal: true

module Rack
  module Auth
    class Digest
      # Parses the Authorization header of an incoming Digest request.
      class Request < Auth::AbstractRequest
        ATTRIBUTES = %w[
          username realm nonce uri response cnonce opaque nc qop algorithm
        ].freeze

        def digest?
          'digest' == scheme
        end

        def params
          @parsed_params ||= Params.parse(super)
        end

        ATTRIBUTES.each do |key|
          define_method(key) { params[key] }
        end

        # All attributes the middleware needs in order to verify the
        # credentials are present and non-empty.
        def complete?
          %w[username realm nonce uri response qop nc cnonce].all? do |key|
            value = params[key]
            value.is_a?(String) && !value.empty?
          end
        end
      end
    end
  end
end

