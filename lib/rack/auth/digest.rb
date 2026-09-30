# frozen_string_literal: true

require 'digest'
require 'securerandom'

require_relative '../utils'
require_relative 'abstract/handler'
require_relative 'abstract/request'

module Rack
  module Auth
    # Rack::Auth::Digest implements HTTP Digest Access Authentication as
    # per RFC 7616, using the SHA-256 and SHA-256-sess algorithms with the
    # +auth+ and +auth-int+ quality of protection modes.
    #
    # Initialize with the Rack application to protect, a +realm+, and a
    # block mapping a username to its stored user digest (HA1, the
    # hexadecimal digest of "username:realm:password"), returning nil for
    # unknown users:
    #
    #   Rack::Auth::Digest.new(app, realm: 'restricted') do |username|
    #     user_digest_store[username]
    #   end
    #
    # Issued nonces and nonce-count replay records are kept in an
    # injectable store, binding every nonce to server-side state with an
    # expiry. See Rack::Auth::Digest::MemoryNonceStore for the interface
    # and pass a custom implementation via +nonce_store:+.
    #
    # Responses to stale (expired) nonces carry +stale=true+ in the
    # challenge so clients can retry silently with a fresh nonce; plainly
    # invalid credentials are challenged without it.
    class Digest < AbstractHandler
      ALGORITHMS = %w[SHA-256 SHA-256-sess].freeze
      QOPS = %w[auth auth-int].freeze

      def initialize(app, realm:, algorithm: 'SHA-256', qops: QOPS,
                     nonce_ttl: 300, opaque: nil, clock: -> { Time.now },
                     nonce_store: nil, &user_digest)
        super(app, realm, &user_digest)

        algorithm = ALGORITHMS.find { |known| known.casecmp?(algorithm.to_s) }
        unless algorithm
          raise ArgumentError, "unsupported digest algorithm: #{algorithm}"
        end

        qops = qops.map(&:to_s)
        unless qops.any? && (qops - QOPS).empty?
          raise ArgumentError, "qops must be drawn from: #{QOPS.join(', ')}"
        end

        @algorithm = algorithm
        @qops = qops
        @nonce_ttl = nonce_ttl
        @opaque = opaque || SecureRandom.hex(16)
        @clock = clock
        @nonce_store = nonce_store || MemoryNonceStore.new(clock: clock)
      end

      def call(env)
        auth = Request.new(env)

        return unauthorized unless auth.provided?
        return bad_request unless auth.digest?
        return bad_request unless auth.complete?

        case verify(auth, env)
        when :ok
          env['REMOTE_USER'] = auth.username
          @app.call(env)
        when :stale
          unauthorized(challenge(stale: true))
        else
          unauthorized
        end
      end

      # The hexadecimal SHA-256 digest of +string+; the hash function
      # shared by both supported algorithms.
      def self.h(string)
        ::Digest::SHA256.hexdigest(string)
      end

      private

      def verify(auth, env)
        return :invalid unless auth.algorithm && @algorithm.casecmp?(auth.algorithm)
        return :invalid unless @qops.include?(auth.qop)
        return :invalid unless auth.opaque == @opaque
        return :invalid unless realm.nil? || auth.realm == realm
        return :invalid unless auth.nc =~ /\A[0-9a-f]{8}\z/i

        expires_at = @nonce_store.expires_at(auth.nonce)
        return :invalid if expires_at.nil?
        return :stale unless expires_at > @clock.call

        return :invalid unless @nonce_store.claim(auth.nonce, auth.nc)

        user_digest = @authenticator.call(auth.username)
        return :invalid if user_digest.nil?

        expected = expected_response(auth, env, user_digest)
        return :invalid unless Utils.secure_compare(expected, auth.response.to_s)

        :ok
      end

      def expected_response(auth, env, user_digest)
        ha1 = user_digest
        ha1 = self.class.h("#{ha1}:#{auth.nonce}:#{auth.cnonce}") if sess?
        self.class.h("#{ha1}:#{auth.nonce}:#{auth.nc}:#{auth.cnonce}:#{auth.qop}:#{ha2(auth, env)}")
      end

      def ha2(auth, env)
        if auth.qop == 'auth-int'
          self.class.h("#{env['REQUEST_METHOD']}:#{auth.uri}:#{entity_digest(env)}")
        else
          self.class.h("#{env['REQUEST_METHOD']}:#{auth.uri}")
        end
      end

      # Reads the request entity so its digest can be verified, then
      # rewinds the input so the application still receives every byte.
      # Requests without a body (rack.input may be nil) digest as the
      # empty entity.
      def entity_digest(env)
        entity = if (input = env['rack.input'])
                   input.read.tap { input.rewind }
                 else
                   ''
                 end
        self.class.h(entity)
      end

      def sess?
        @algorithm == 'SHA-256-sess'
      end

      def challenge(stale: false)
        nonce = SecureRandom.hex(16)
        @nonce_store.record(nonce, @clock.call + @nonce_ttl)

        parts = [
          "realm=#{Params.quote(realm)}",
          "qop=#{Params.quote(@qops.join(','))}",
          "algorithm=#{@algorithm}",
          "nonce=#{Params.quote(nonce)}",
          "opaque=#{Params.quote(@opaque)}"
        ]
        parts << 'stale=true' if stale
        "Digest #{parts.join(', ')}"
      end
    end
  end
end

require_relative 'digest/params'
require_relative 'digest/request'
require_relative 'digest/nonce_store'
