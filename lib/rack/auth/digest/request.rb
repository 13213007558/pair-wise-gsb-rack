# frozen_string_literal: true

require_relative '../abstract/request'
require_relative 'params'

require 'stringio'

module Rack
  module Auth
    class Digest
      class Request < Auth::AbstractRequest
        # Set by the middleware before verification, so the entity
        # digest for qop=auth-int is computed with the same hash.
        attr_accessor :digest

        def digest?
          'digest' == scheme
        end

        def params
          @params ||= Params.parse(super)
        end

        def method
          @env[Rack::REQUEST_METHOD]
        end

        %w[username realm nonce uri response cnonce opaque qop nc].each do |key|
          define_method(key) { params[key] }
        end

        def algorithm
          params['algorithm'] || 'SHA-256'
        end

        # Hex digest of the request entity body. The body is fully
        # read and then restored -- by rewinding the input when
        # possible, otherwise by swapping in a buffer holding every
        # byte read -- so the application downstream still receives
        # the complete body.
        def entity_digest
          input = @env[Rack::RACK_INPUT]
          hasher = digest.new
          return hasher.hexdigest unless input

          buffer = StringIO.new
          buffer.set_encoding(Encoding::BINARY)
          while (chunk = input.read(16 * 1024))
            hasher.update(chunk)
            buffer.write(chunk)
          end

          if input.respond_to?(:rewind)
            input.rewind
          else
            buffer.rewind
            @env[Rack::RACK_INPUT] = buffer
          end

          hasher.hexdigest
        end
      end
    end
  end
end
