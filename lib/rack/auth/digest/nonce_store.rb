# frozen_string_literal: true

module Rack
  module Auth
    class Digest
      # NonceStore records (nonce, nonce-count) pairs the server has
      # already accepted, so replayed requests can be rejected.
      #
      # This is the injectable replay-record interface: pass any
      # object responding to #record(nonce, nonce_count) as the
      # :nonce_store option of Rack::Auth::Digest. #record must
      # atomically return true the first time a pair is seen and
      # false for every subsequent attempt, including concurrent
      # ones.
      class NonceStore
        def record(nonce, nonce_count)
          raise NotImplementedError
        end
      end

      # Default in-memory NonceStore. A mutex makes the check-and-set
      # atomic, so of concurrent requests carrying the same nonce and
      # nonce-count exactly one is accepted.
      class InMemoryNonceStore < NonceStore
        def initialize
          @mutex = Mutex.new
          @seen = {}
        end

        def record(nonce, nonce_count)
          @mutex.synchronize do
            counts = (@seen[nonce] ||= {})
            return false if counts[nonce_count]

            counts[nonce_count] = true
            true
          end
        end
      end
    end
  end
end
