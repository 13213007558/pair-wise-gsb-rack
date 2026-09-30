# frozen_string_literal: true

require 'openssl'
require 'securerandom'

module Rack
  module Auth
    class Digest
      # Nonce generates and validates server nonces. Each nonce is
      # bound to server side state: it carries an HMAC keyed with a
      # secret held only by this server instance, over the timestamp
      # and random payload, so clients cannot forge or extend a
      # nonce. The embedded timestamp gives every nonce a limited
      # lifetime.
      class Nonce
        class << self
          def generate(secret, clock = -> { Time.now })
            issued_at = clock.call.to_i
            payload = "#{issued_at}:#{SecureRandom.hex(16)}"
            "#{encode(payload)}.#{encode(mac(secret, payload))}"
          end

          # Returns :fresh when the nonce is authentic and unexpired,
          # :stale when it is authentic but older than +ttl+ seconds,
          # and nil when it is not authentic at all.
          def validate(nonce, secret, ttl, clock = -> { Time.now })
            payload, mac = nonce.to_s.split('.', 2).map { |part| decode(part) }
            return nil if payload.nil? || mac.nil?
            return nil unless secure_compare(mac, self.mac(secret, payload))

            issued_at = payload.split(':', 2).first.to_i
            (clock.call.to_i - issued_at) > ttl ? :stale : :fresh
          end

          private

          def mac(secret, payload)
            OpenSSL::HMAC.digest(OpenSSL::Digest::SHA256.new, secret, payload)
          end

          def encode(str)
            str.unpack1('H*')
          end

          def decode(str)
            [str.to_s].pack('H*')
          rescue ArgumentError
            nil
          end

          def secure_compare(a, b)
            a.bytesize == b.bytesize &&
              OpenSSL.fixed_length_secure_compare(a, b)
          end
        end
      end
    end
  end
end
