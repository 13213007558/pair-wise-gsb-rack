# frozen_string_literal: true

module Rack
  module Auth
    class Digest
      # Parses the comma separated key=value pairs of a Digest
      # Authorization header, honouring quoted strings (which may
      # contain commas and backslash escaped characters, per
      # RFC 9110 quoted-string rules).
      class Params < Hash
        def self.parse(str)
          params = new

          until str.nil? || str.empty?
            match = /\s*([a-zA-Z][a-zA-Z0-9_-]*)\s*=\s*/.match(str)
            return params unless match
            key = match[1]
            str = match.post_match

            if str.start_with?('"')
              value = +''
              str = str[1..]
              until str.empty?
                char = str.slice!(0)
                case char
                when '\\'
                  value << str.slice!(0).to_s
                when '"'
                  break
                else
                  value << char
                end
              end
            else
              match = /([^,\s]+)\s*/.match(str)
              return params unless match
              value = match[1]
              str = match.post_match
            end

            params[key] = value

            str = str.sub(/\s*,\s*/, '')
          end

          params
        end
      end
    end
  end
end
