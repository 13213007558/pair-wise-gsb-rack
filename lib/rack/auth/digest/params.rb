# frozen_string_literal: true

require 'strscan'

module Rack
  module Auth
    class Digest
      # Parses and serializes the comma-separated attribute lists used in
      # Digest challenge and credentials headers. Quoted values may contain
      # commas and backslash-escaped characters (including quotes), as
      # commonly produced for usernames and realms.
      module Params
        TOKEN = /[!#$%&'*+\-.^_|~0-9A-Za-z]+/

        module_function

        def parse(string)
          params = {}
          return params if string.nil?

          scanner = StringScanner.new(string)
          until scanner.eos?
            scanner.skip(/[\s,]+/)
            break if scanner.eos?

            key = scanner.scan(TOKEN)
            break unless key

            scanner.skip(/\s*/)
            break unless scanner.scan(/=/)
            scanner.skip(/\s*/)

            params[key] = scan_value(scanner)
          end
          params
        end

        def quote(string)
          %("#{string.to_s.gsub(/["\\]/) { |char| "\\#{char}" }}")
        end

        def scan_value(scanner)
          return scanner.scan(/[^,]*/).to_s.strip unless scanner.scan(/"/)

          value = String.new
          until scanner.eos?
            if (chunk = scanner.scan(/[^"\\]+/))
              value << chunk
            elsif scanner.scan(/\\(.)/m)
              value << scanner[1]
            else
              scanner.scan(/"/)
              break
            end
          end
          value
        end
      end
    end
  end
end
