# frozen_string_literal: true

module Rack
  module Auth
    class Digest
      # In-memory implementation of the nonce store used by
      # Rack::Auth::Digest, keeping both issued nonces and nonce-count
      # replay records in server-side state.
      #
      # A nonce store must implement:
      #
      # +record(nonce, expires_at)+:: Remember a freshly issued nonce and
      #     its expiry time, binding the nonce to server-side state.
      # +expires_at(nonce)+:: The expiry time of a known nonce, or nil if
      #     the nonce was never issued (or has been forgotten). Expired
      #     nonces may still be reported; the middleware compares the
      #     expiry against its own clock to tell stale nonces apart from
      #     invalid ones.
      # +claim(nonce, nc)+:: Atomically register the nonce-count for a
      #     nonce, returning true the first time a (nonce, nc) pair is
      #     seen and false on replay. Must be safe for concurrent calls:
      #     of any number of simultaneous claims for the same pair, at
      #     most one may return true.
      #
      # The clock is injectable to make expiry deterministic in tests.
      class MemoryNonceStore
        def initialize(clock: -> { Time.now })
          @clock = clock
          @nonces = {}
          @claims = {}
          @mutex = Mutex.new
        end

        def record(nonce, expires_at)
          @mutex.synchronize do
            purge(@clock.call)
            @nonces[nonce] = expires_at
          end
          nil
        end

        def expires_at(nonce)
          @mutex.synchronize { @nonces[nonce] }
        end

        def claim(nonce, nc)
          @mutex.synchronize do
            used = (@claims[nonce] ||= {})
            if used[nc]
              false
            else
              used[nc] = true
            end
          end
        end

        private

        def purge(now)
          @nonces.delete_if do |nonce, expires_at|
            if expires_at <= now
              @claims.delete(nonce)
              true
            end
          end
        end
      end
    end
  end
end

