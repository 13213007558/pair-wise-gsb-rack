# frozen_string_literal: true

require 'openssl'

require_relative 'constants'
require_relative 'utils'

module Rack
  # Rack::MessageSignatures verifies HTTP Message Signatures (RFC 9421) on
  # incoming requests before passing them to the application.
  #
  # Only the +hmac-sha256+ signature algorithm is supported. Shared secrets
  # are resolved locally through the +keys+ option, which may be a Hash of
  # keyid to secret, or a callable accepting a keyid and returning the
  # secret (or +nil+).
  #
  #   Rack::MessageSignatures.new(app,
  #     keys: { "partner-key" => "shared-secret" },
  #     required_components: ["@method", "@authority", "date"],
  #     allowed_keyids: ["partner-key"],
  #     max_age: 300)
  #
  # A request may carry several signatures. Each labeled signature is
  # evaluated on its own: the request is accepted only if at least one
  # signature, by itself, covers every required component (in the configured
  # order), satisfies the keyid and freshness policy, and verifies
  # cryptographically. Coverage from distinct signatures is never combined.
  # When no signature qualifies, the application is not called and a 401
  # response is returned.
  class MessageSignatures
    HMAC_SHA256 = 'hmac-sha256'

    # Raised when a structured field (RFC 8941) cannot be parsed.
    class ParseError < StandardError; end

    # Raised when a covered component cannot be resolved for a request.
    class ComponentError < StandardError; end

    # Bare values of an RFC 8941 item that are not strings or numbers.
    Token = Struct.new(:value)
    ByteSequence = Struct.new(:value)

    # Minimal RFC 8941 structured fields parser. Supports dictionaries whose
    # members are items or inner lists, with parameters, which is everything
    # needed for the Signature-Input and Signature fields.
    class Parser
      TOKEN_CHARS = /[A-Za-z0-9!#$%&'*+\-.^_\x60|~:\/]/
      KEY_CHARS = /[a-z0-9_*\-.]/

      def self.parse_dictionary(input)
        new(input).parse_dictionary
      end

      def initialize(input)
        @input = input
        @pos = 0
      end

      def parse_dictionary
        members = {}
        skip_ows
        until eof?
          key = parse_key
          if peek == '='
            advance
            member = parse_item_or_inner_list
          else
            member = [true, parse_parameters]
          end
          raise ParseError, "duplicate dictionary member #{key.inspect}" if members.key?(key)
          members[key] = member
          skip_ows
          break if eof?
          expect(',')
          skip_ows
          raise ParseError, 'trailing comma in dictionary' if eof?
        end
        members
      end

      private

      def parse_item_or_inner_list
        if peek == '('
          advance
          items = []
          loop do
            skip_sp
            raise ParseError, 'unterminated inner list' if eof?
            break if peek == ')'
            items << parse_item
            raise ParseError, 'bad inner list separator' unless eof? || peek == ')' || peek == ' '
            skip_sp
          end
          expect(')')
          [items, parse_parameters]
        else
          parse_item
        end
      end

      # Returns [bare_value, parameters].
      def parse_item
        [parse_bare, parse_parameters]
      end

      def parse_bare
        case peek
        when '"' then parse_string
        when ':' then parse_byte_sequence
        when /[0-9-]/ then parse_number
        when /[A-Za-z*]/ then parse_token
        else raise ParseError, "unexpected character #{peek.inspect}"
        end
      end

      def parse_string
        expect('"')
        out = String.new
        until eof?
          char = advance
          case char
          when '"'
            return out
          when '\\'
            raise ParseError, 'dangling escape in string' if eof?
            escaped = advance
            raise ParseError, 'invalid escape in string' unless escaped == '"' || escaped == '\\'
            out << escaped
          else
            raise ParseError, 'invalid character in string' if char.ord < 0x20 || char.ord > 0x7e
            out << char
          end
        end
        raise ParseError, 'unterminated string'
      end

      def parse_byte_sequence
        expect(':')
        start = @pos
        advance while !eof? && @input[@pos].match?(/[A-Za-z0-9+\/=]/)
        raise ParseError, 'unterminated byte sequence' if eof?
        value = @input[start...@pos]
        expect(':')
        ByteSequence.new(value)
      end

      def parse_number
        start = @pos
        advance if peek == '-'
        raise ParseError, 'bad number' if eof? || !peek.match?(/[0-9]/)
        advance while !eof? && peek.match?(/[0-9]/)
        if !eof? && peek == '.'
          advance
          raise ParseError, 'bad decimal' if eof? || !peek.match?(/[0-9]/)
          advance while !eof? && peek.match?(/[0-9]/)
          return Float(@input[start...@pos])
        end
        Integer(@input[start...@pos], 10)
      end

      def parse_token
        start = @pos
        advance
        advance while !eof? && peek.match?(TOKEN_CHARS)
        Token.new(@input[start...@pos])
      end

      def parse_key
        raise ParseError, 'bad dictionary key' if eof? || !peek.match?(/[a-z*]/)
        start = @pos
        advance
        advance while !eof? && peek.match?(KEY_CHARS)
        @input[start...@pos]
      end

      # Returns an ordered list of [key, value] pairs, preserving order so
      # that signature parameters can be re-serialized exactly.
      def parse_parameters
        params = []
        while peek == ';'
          advance
          skip_ows
          key = parse_key
          value = true
          if peek == '='
            advance
            value = parse_bare
          end
          raise ParseError, "duplicate parameter #{key.inspect}" if params.any? { |k, _| k == key }
          params << [key, value]
        end
        params
      end

      def skip_ows
        advance while !eof? && (peek == ' ' || peek == "\t")
      end

      def skip_sp
        advance while !eof? && peek == ' '
      end

      def peek
        @input[@pos]
      end

      def advance
        char = @input[@pos]
        @pos += 1
        char
      end

      def expect(char)
        raise ParseError, "expected #{char.inspect}" unless peek == char
        advance
      end

      def eof?
        @pos >= @input.length
      end
    end

    # Canonical RFC 8941 serialization, used to rebuild the
    # @signature-params line of the signature base.
    module Serialize
      module_function

      def string(value)
        %("#{value.gsub(/[\\"]/) { |char| "\\#{char}" }}")
      end

      def bare(value)
        case value
        when String then string(value)
        when Token then value.value
        when Integer then value.to_s
        when ByteSequence then ":#{value.value}:"
        else raise ParseError, "cannot serialize #{value.class}"
        end
      end

      def parameters(params)
        params.map { |key, value| value == true ? ";#{key}" : ";#{key}=#{bare(value)}" }.join
      end

      def inner_list(items, params)
        "(#{items.map { |value, item_params| bare(value) + parameters(item_params) }.join(' ')})#{parameters(params)}"
      end
    end

    def initialize(app, keys:, required_components: [], allowed_keyids: nil, max_age: nil, clock_skew: 60)
      @app = app
      @keys = keys
      @required_components = required_components
      @allowed_keyids = allowed_keyids
      @max_age = max_age
      @clock_skew = clock_skew
    end

    def call(env)
      if verified?(env)
        @app.call(env)
      else
        unauthorized
      end
    end

    private

    def verified?(env)
      inputs = parse_dictionary_header(env, 'HTTP_SIGNATURE_INPUT')
      signatures = parse_dictionary_header(env, 'HTTP_SIGNATURE')
      return false unless inputs && signatures && !inputs.empty?

      inputs.any? do |label, (components, signature_params)|
        verify_signature(env, components, signature_params, signatures[label])
      end
    end

    def parse_dictionary_header(env, key)
      value = env[key]
      return nil unless value
      Parser.parse_dictionary(value)
    rescue ParseError
      nil
    end

    # Evaluates a single labeled signature. Every check must pass for this
    # signature alone; nothing is inherited from other signatures.
    def verify_signature(env, components, signature_params, signature_entry)
      return false unless components.is_a?(Array) # must be an inner list
      return false unless signature_entry

      signature, = signature_entry
      return false unless signature.is_a?(ByteSequence)

      params = signature_params.to_h
      return false unless acceptable_algorithm?(params['alg'])

      keyid = params['keyid']
      return false unless keyid.is_a?(String)
      return false if @allowed_keyids && !@allowed_keyids.include?(keyid)

      secret = lookup_key(keyid)
      return false unless secret
      return false unless fresh?(params['created'], params['expires'])

      covered = components.map do |identifier, component_params|
        raise ComponentError, 'component identifier must be a string' unless identifier.is_a?(String)
        [identifier, component_params]
      end
      keys = covered.map { |identifier, component_params| component_key(identifier, component_params) }
      return false unless keys.uniq.length == keys.length
      return false unless required_components_covered?(keys)

      base = signature_base(env, covered, signature_params)
      expected = OpenSSL::HMAC.digest('sha256', secret, base)
      provided = decode_base64(signature.value)
      return false unless provided
      provided.bytesize == expected.bytesize && Utils.secure_compare(provided, expected)
    rescue ArgumentError, ComponentError
      false
    end

    # Strict Base64 decoding (RFC 4648) without the base64 library.
    def decode_base64(value)
      return nil unless value.length % 4 == 0 && value.match?(/\A[A-Za-z0-9+\/]*={0,2}\z/)
      value.unpack1('m')
    rescue ArgumentError
      nil
    end

    def acceptable_algorithm?(alg)
      case alg
      when nil then true
      when String then alg == HMAC_SHA256
      when Token then alg.value == HMAC_SHA256
      else false
      end
    end

    def lookup_key(keyid)
      case @keys
      when Hash then @keys[keyid]
      else @keys.call(keyid)
      end
    end

    def fresh?(created, expires)
      return false if created && !created.is_a?(Integer)
      return false if expires && !expires.is_a?(Integer)

      now = Time.now.to_i
      return false if expires && now > expires

      if created
        return false if created > now + @clock_skew
        return false if @max_age && now - created > @max_age
      elsif @max_age
        # A validity window cannot be enforced without a created parameter.
        return false
      end

      true
    end

    # The required components must be covered in the configured order.
    def required_components_covered?(covered_keys)
      remaining = covered_keys.dup
      @required_components.all? do |required|
        if (index = remaining.index(required))
          remaining = remaining[(index + 1)..]
          true
        else
          false
        end
      end
    end

    def component_key(identifier, params)
      identifier + Serialize.parameters(params)
    end

    def signature_base(env, covered, signature_params)
      lines = covered.map do |identifier, component_params|
        "#{Serialize.string(identifier)}#{Serialize.parameters(component_params)}: #{component_value(env, identifier, component_params)}"
      end
      lines << %("@signature-params": #{Serialize.inner_list(covered, signature_params)})
      lines.join("\n")
    end

    def component_value(env, identifier, params)
      if identifier.start_with?('@')
        derived_component_value(env, identifier, params)
      else
        raise ComponentError, 'field component parameters are not supported' unless params.empty?
        field_value(env, identifier)
      end
    end

    def derived_component_value(env, identifier, params)
      case identifier
      when '@method'
        no_params!(identifier, params)
        env[REQUEST_METHOD].to_s
      when '@authority'
        no_params!(identifier, params)
        authority(env)
      when '@path'
        no_params!(identifier, params)
        path = "#{env[SCRIPT_NAME]}#{env[PATH_INFO]}"
        path.empty? ? '/' : path
      when '@query'
        no_params!(identifier, params)
        "?#{env[QUERY_STRING]}"
      when '@query-param'
        name = query_param_name(identifier, params)
        query_param_value(env[QUERY_STRING].to_s, name)
      else
        raise ComponentError, "unsupported derived component #{identifier.inspect}"
      end
    end

    def no_params!(identifier, params)
      raise ComponentError, "parameters not allowed on #{identifier}" unless params.empty?
    end

    def query_param_name(identifier, params)
      unless params.length == 1 && params[0][0] == 'name' && params[0][1].is_a?(String)
        raise ComponentError, "#{identifier} requires exactly one string name parameter"
      end
      params[0][1]
    end

    # RFC 9421 2.2.9: the parameter must occur exactly once. Multiple
    # occurrences are ambiguous and rejected; a missing parameter is an
    # error; an empty value serializes as an empty string.
    def query_param_value(query_string, name)
      values = []
      query_string.split('&', -1).each do |pair|
        pair_name, _, pair_value = pair.partition('=')
        values << Utils.unescape(pair_value) if Utils.unescape(pair_name) == name
      end
      raise ComponentError, "query parameter #{name.inspect} missing or repeated" unless values.length == 1
      values.first
    end

    def authority(env)
      if (host = env['HTTP_HOST'])
        host.downcase
      else
        name = env[SERVER_NAME].to_s.downcase
        port = env[SERVER_PORT].to_s
        default = env['rack.url_scheme'] == 'https' ? '443' : '80'
        port.empty? || port == default ? name : "#{name}:#{port}"
      end
    end

    # RFC 9421 2.1: multiple field lines are combined with ", " and
    # leading/trailing whitespace is stripped. A missing field is an error;
    # an empty field value serializes as an empty string.
    def field_value(env, name)
      key =
        case name.downcase
        when 'content-type' then 'CONTENT_TYPE'
        when 'content-length' then 'CONTENT_LENGTH'
        else "HTTP_#{name.upcase.tr('-', '_')}"
        end
      value = env[key]
      raise ComponentError, "missing field #{name.inspect}" unless value
      value.split("\n", -1).map { |line| line.strip }.join(', ')
    end

    def unauthorized
      [401,
        { CONTENT_TYPE => 'text/plain',
          CONTENT_LENGTH => '0' },
        []]
    end
  end
end
