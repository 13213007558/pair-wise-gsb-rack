# frozen_string_literal: true

require 'openssl'
require 'securerandom'

require_relative '../utils'
require_relative 'abstract/handler'

module Rack
  module Auth
    # Rack::Auth::Digest implements HTTP Digest Authentication per
    # RFC 7616, using the SHA-256 and SHA-256-sess algorithms and
    # the auth and auth-int quality of protection options.
    #
    # Initialize with the Rack application that you want protecting,
    # and a block (or the :password_lookup option) that returns the
    # password for a given username, or nil when the user is unknown.
    # With :hashed_passwords, the lookup must instead return the
    # precomputed HA1, i.e. SHA256(username:realm:password).
    #
    # Server state is injectable: :nonce_store receives the replay
    # records (see Rack::Auth::Digest::NonceStore) and :clock
    # supplies the current time, which the nonce lifetime checks
    # (:nonce_ttl, in seconds) are based on.
    class Digest < AbstractHandler
      QOP_AUTH = 'auth'
      QOP_AUTH_INT = 'auth-int'
      QOPS = [QOP_AUTH, QOP_AUTH_INT].freeze

      ALGORITHMS = {
        'SHA-256' => false,
        'SHA-256-SESS' => true,
      }.freeze

      DEFAULT_NONCE_TTL = 300

      attr_reader :nonce_store, :clock, :nonce_ttl, :opaque

      def initialize(app, realm = nil, **options, &password_lookup)
        super(app, realm, &(options[:password_lookup] || password_lookup))
        @passwords_hashed = options.fetch(:hashed_passwords, false)
        @nonce_store = options[:nonce_store] || InMemoryNonceStore.new
        @clock = options[:clock] || -> { Time.now }
        @nonce_ttl = options.fetch(:nonce_ttl, DEFAULT_NONCE_TTL)
        @secret = options[:secret] || SecureRandom.hex(32)
        @opaque = options[:opaque] || OpenSSL::HMAC.hexdigest(
          OpenSSL::Digest::SHA256.new, @secret, 'rack-digest-opaque')
      end

      def call(env)
        auth = Request.new(env)
        auth.digest = OpenSSL::Digest::SHA256

        return unauthorized unless auth.provided?

        return bad_request unless auth.digest?

        return unauthorized unless valid?(auth)

        if valid_nonce?(auth)
          if valid_credentials?(auth) && record_nonce_count(auth)
            env['REMOTE_USER'] = auth.username
            return @app.call(env)
          end

          # The nonce itself is fine; the credentials or the nonce
          # count are not. Rechallenge without stale so the client
          # retries with the same nonce.
          return unauthorized
        end

        # The nonce is authentic but expired: tell the client to
        # retry with the fresh nonce from this challenge.
        return unauthorized(challenge(stale: true)) if stale_nonce?(auth)

        unauthorized
      end

      private

      def valid?(auth)
        valid_qop?(auth) && valid_algorithm?(auth) && valid_opaque?(auth)
      end

      def valid_qop?(auth)
        QOPS.include?(auth.qop)
      end

      def valid_algorithm?(auth)
        ALGORITHMS.key?(auth.algorithm.to_s.upcase)
      end

      def valid_opaque?(auth)
        Rack::Utils.secure_compare(auth.opaque.to_s, opaque)
      end

      def valid_nonce?(auth)
        :fresh == Nonce.validate(auth.nonce, @secret, nonce_ttl, clock)
      end

      def stale_nonce?(auth)
        :stale == Nonce.validate(auth.nonce, @secret, nonce_ttl, clock)
      end

      # Records the (nonce, nonce-count) pair in the replay store.
      # Only the first request with a given pair is accepted; any
      # replay, even a concurrent one, is rejected.
      def record_nonce_count(auth)
        nonce_store.record(auth.nonce, auth.nc)
      end

      def valid_credentials?(auth)
        Rack::Utils.secure_compare(auth.response.to_s, expected_response(auth))
      end

      def expected_response(auth)
        hash("#{ha1(auth)}:#{auth.nonce}:#{auth.nc}:#{auth.cnonce}:#{auth.qop}:#{ha2(auth)}")
      end

      def ha1(auth)
        a1 = lookup_password(auth)
        a1 = hash(a1) unless @passwords_hashed
        return a1 unless sess?(auth)

        hash("#{a1}:#{auth.nonce}:#{auth.cnonce}")
      end

      def ha2(auth)
        a2 = "#{auth.method}:#{auth.uri}"
        a2 = "#{a2}:#{auth.entity_digest}" if QOP_AUTH_INT == auth.qop
        hash(a2)
      end

      def sess?(auth)
        ALGORITHMS[auth.algorithm.to_s.upcase]
      end

      def lookup_password(auth)
        password = @authenticator.call(auth.username)
        return '' if password.nil?

        @passwords_hashed ? password : "#{auth.username}:#{realm}:#{password}"
      end

      def hash(data)
        OpenSSL::Digest::SHA256.hexdigest(data)
      end

      def challenge(stale: false)
        parts = [
          %(Digest realm="#{realm}"),
          %(qop="#{QOPS.join(',')}"),
          'algorithm=SHA-256',
          %(nonce="#{Nonce.generate(@secret, clock)}"),
          %(opaque="#{opaque}"),
        ]
        parts << 'stale=true' if stale
        parts.join(', ')
      end
    end
  end
end

# Required after the class definition above: these files reopen
# Rack::Auth::Digest to nest their own classes inside it.
require_relative 'digest/nonce'
require_relative 'digest/nonce_store'
require_relative 'digest/params'
require_relative 'digest/request'
