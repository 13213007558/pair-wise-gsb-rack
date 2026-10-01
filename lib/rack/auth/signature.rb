# frozen_string_literal: true

require 'openssl'
require 'uri'

require_relative '../constants'
require_relative '../utils'

module Rack
  module Auth
    # Verify RFC 9421 HTTP message signatures using HMAC-SHA256.
    class Signature
      HMAC_SHA256 = 'hmac-sha256'
      CONTENT_TYPE = 'text/plain'
      SHA256_DIGEST_LENGTH = 32

      SIGNATURE_HEADER = 'HTTP_SIGNATURE'
      SIGNATURE_INPUT_HEADER = 'HTTP_SIGNATURE_INPUT'

      UNRESERVED_CHARACTERS = (('a'..'z').to_a + ('A'..'Z').to_a + ('0'..'9').to_a +
        ['-', '.', '_', '~']).freeze
      PATH_CHARACTERS = (UNRESERVED_CHARACTERS +
        ['!', '$', '&', "'", '(', ')', '*', '+', ',', ';', '=', ':', '@', '/']).freeze
      QUERY_CHARACTERS = (PATH_CHARACTERS + ['?']).freeze
      QUERY_PARAM_CHARACTERS = UNRESERVED_CHARACTERS

      class SignatureError < StandardError; end
      class MalformedSignature < SignatureError; end

      def initialize(app, required_components:, allowed_keyids:, key_resolver: nil,
                     max_age: nil, clock_skew: 0, require_created: false,
                     clock: -> { Time.now }, &block)
        raise ArgumentError, 'required_components must not be empty' if required_components.empty?
        raise ArgumentError, 'allowed_keyids must not be empty' if allowed_keyids.empty?
        raise ArgumentError, 'key_resolver is required' unless key_resolver || block

        @app = app
        @required_components = required_components.map { |component| canonical_component(component) }
        @allowed_keyids = allowed_keyids
        @key_resolver = key_resolver || block
        @max_age = max_age
        @clock_skew = clock_skew
        @require_created = require_created || !max_age.nil?
        @clock = clock
      end

      def call(env)
        return unauthorized unless request_authorized?(env)

        @app.call(env)
      end

      private

      def request_authorized?(env)
        signatures = parse_dictionary(env[SIGNATURE_HEADER])
        inputs = parse_dictionary(env[SIGNATURE_INPUT_HEADER])
        return false if signatures.empty?
        return false unless signatures.keys.sort == inputs.keys.sort

        signatures.any? do |label, (signature, signature_parameters)|
          valid_candidate?(env, label, signature, signature_parameters, inputs.fetch(label).first)
        end
      rescue MalformedSignature
        false
      end

      def valid_candidate?(env, label, signature, signature_parameters, input)
        return false unless signature_parameters.empty?
        return false unless signature.is_a?(StructuredFields::ByteSequence)
        return false unless signature.value.bytesize == SHA256_DIGEST_LENGTH
        return false unless input.is_a?(Array)

        items, parameters = input
        keyid = string_parameter(parameters, 'keyid')
        return false unless keyid && @allowed_keyids.include?(keyid)
        return false unless string_parameter(parameters, 'alg') == HMAC_SHA256

        validate_timing(parameters)
        base = signature_base(env, items, parameters)
        key = @key_resolver.call(keyid)
        return false unless key.is_a?(String)

        expected = OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), key.b, base)
        Utils.secure_compare(expected, signature.value.b)
      rescue SignatureError
        false
      end

      def validate_timing(parameters)
        created = integer_parameter(parameters, 'created', required: @require_created)
        expires = integer_parameter(parameters, 'expires')
        now = @clock.call.to_i

        raise SignatureError, 'signature is from the future' if created && created > now + @clock_skew
        raise SignatureError, 'signature is expired' if expires && now > expires + @clock_skew
        raise SignatureError, 'created must precede expires' if created && expires && expires < created
        raise SignatureError, 'signature is too old' if created && @max_age && now - @clock_skew > created + @max_age
      end

      def signature_base(env, items, signature_parameters)
        identifiers = []
        seen = {}
        has_query = false
        has_query_param = false

        lines = items.map do |item|
          name, parameters = component_identifier(item)
          identifier = StructuredFields.serialize_component(name, parameters)
          raise SignatureError, "component is repeated: #{identifier}" if seen[identifier]

          seen[identifier] = true
          identifiers << identifier
          ensure_component_allowed(name, parameters)
          has_query = true if name == '@query'
          has_query_param = true if name == '@query-param'

          "#{identifier}: #{component_value(env, name, parameters)}"
        end

        raise SignatureError, '@query and @query-param cannot be combined' if has_query && has_query_param
        ensure_required_components(identifiers)

        lines << "\"@signature-params\": #{StructuredFields.serialize_inner_list(items, signature_parameters)}"
        lines.join("\n")
      end

      def ensure_required_components(identifiers)
        @required_components.each do |required|
          index = identifiers.index(required)
          raise SignatureError, "required component is missing: #{required}" unless index

          identifiers = identifiers[(index + 1)..-1] || []
        end
      end

      def component_identifier(item)
        unless item.is_a?(Array) && item.length == 2 && item.first.is_a?(String) && item.last.is_a?(Hash)
          raise MalformedSignature, 'signature component must be a string with parameters'
        end

        item
      end

      def component_value(env, name, parameters)
        case name
        when '@method'
          no_component_parameters(name, parameters)
          StructuredFields.serialize_string(env[Rack::REQUEST_METHOD].to_s)
        when '@authority'
          no_component_parameters(name, parameters)
          StructuredFields.serialize_string(authority(env))
        when '@path'
          no_component_parameters(name, parameters)
          StructuredFields.serialize_string(path(env))
        when '@query'
          no_component_parameters(name, parameters)
          query = env[Rack::QUERY_STRING].to_s
          raise SignatureError, '@query component is not present' if query.empty?

          StructuredFields.serialize_string(p_encode(query, allow: QUERY_CHARACTERS))
        when '@query-param'
          query_param_value(env[Rack::QUERY_STRING].to_s, parameters)
        else
          field_value(env, name, parameters)
        end
      end

      def field_value(env, name, parameters)
        no_component_parameters(name, parameters)
        normalized_name = normalize_field_name(name)
        value = env[env_key(normalized_name)]
        raise SignatureError, "HTTP field is not present: #{normalized_name}" if value.nil?

        lines = Array(value).flat_map { |part| part.to_s.split("\n") }
        field = lines.map { |line| line.sub(/\A[ \t]+/, '').sub(/[ \t]+\z/, '') }.join(', ')
        raise SignatureError, "HTTP field is not present: #{normalized_name}" if field.empty?
        StructuredFields.serialize_string(field)
      end

      def query_param_value(query, parameters)
        name = query_param_name(parameters)
        raise SignatureError, '@query-param component is not present' if query.empty?

        values = query.split('&', -1).map do |pair|
          raw_name, raw_value = pair.split('=', 2)
          raw_name ||= ''
          raw_value ||= ''
          decoded_name = decode_form_component(raw_name)
          next unless decoded_name == name

          p_encode(decode_form_component(raw_value), allow: QUERY_PARAM_CHARACTERS)
        end.compact

        raise SignatureError, "query parameter is missing: #{name}" if values.empty?
        raise SignatureError, "query parameter is repeated: #{name}" if values.length > 1

        StructuredFields.serialize_string(values.first)
      end

      def query_param_name(parameters)
        name = string_parameter(parameters, 'name', required: true)
        raise SignatureError, '@query-param name must not be empty' if name.empty?
        raise SignatureError, '@query-param only accepts a name parameter' unless parameters.keys == ['name']

        decode_form_component(name)
      end

      def no_component_parameters(name, parameters)
        raise SignatureError, "#{name} does not accept parameters" unless parameters.empty?
      end

      def authority(env)
        host = env[Rack::HTTP_HOST]
        return host if host && !host.empty?

        server_name = env[Rack::SERVER_NAME]
        raise SignatureError, '@authority component is not present' unless server_name

        server_port = env[Rack::SERVER_PORT]
        scheme = env[Rack::RACK_URL_SCHEME] || (env[Rack::HTTPS] == 'on' ? 'https' : 'http')
        default_port = scheme == 'https' ? '443' : '80'
        return server_name if !server_port || server_port == default_port

        "#{server_name}:#{server_port}"
      end

      def path(env)
        value = "#{env[Rack::SCRIPT_NAME]}#{env[Rack::PATH_INFO]}"
        raise SignatureError, '@path must be an absolute path' unless value.start_with?('/')

        p_encode(value, allow: PATH_CHARACTERS)
      end

      def env_key(name)
        if name == 'content-type'
          'CONTENT_TYPE'
        elsif name == 'content-length'
          'CONTENT_LENGTH'
        else
          "HTTP_#{name.upcase.tr('-', '_')}"
        end
      end

      def normalize_field_name(name)
        raise SignatureError, "unknown component: #{name}" unless valid_field_name?(name)

        name.downcase
      end

      def valid_field_name?(name)
        !name.start_with?('@') && name.match?(/\A[a-zA-Z!#$%&'*+\-.^`|~][a-zA-Z0-9!#$%&'*+\-.^`|~]*\z/)
      end

      def decode_form_component(value)
        URI.decode_www_form_component(value.b, Encoding::BINARY)
      rescue ArgumentError
        raise MalformedSignature, "invalid query component: #{value}"
      end

      def p_encode(value, allow:)
        binary_value = value.b
        result = String.new.b
        index = 0

        while index < binary_value.bytesize
          byte = binary_value.getbyte(index)
          character = byte.chr

          if allow.include?(character)
            result << character
            index += 1
          elsif character == '%' && binary_value.byteslice(index, 3)&.match?(/\A%[0-9a-fA-F]{2}\z/)
            result << binary_value.byteslice(index, 3)
            index += 3
          else
            result << format('%%%02X', byte)
            index += 1
          end
        end

        result
      end

      def ensure_component_allowed(name, parameters)
        return if %w[@method @authority @path @query @query-param].include?(name)
        return if valid_field_name?(name) && parameters.empty?

        raise SignatureError, "unknown component: #{name}"
      end

      def canonical_component(component)
        case component
        when Symbol then canonical_string_component(component.to_s)
        when String then canonical_string_component(component)
        when Array
          raise ArgumentError, 'invalid component' unless component.length == 2

          canonical_string_component(component.first, canonical_parameters(component.last))
        when Hash
          name = component.fetch(:component, component[:name] || component['name'])
          parameters = component[:parameters] || component['parameters'] || {}
          canonical_string_component(name, canonical_parameters(parameters))
        else
          raise ArgumentError, "invalid component: #{component.inspect}"
        end
      end

      def canonical_string_component(component, parameters = nil)
        if parameters
          name = component.to_s
        elsif component.include?(';')
          name, component_parameters = parse_configured_component(component)
        else
          name = component
          component_parameters = {}
        end

        component_parameters ||= parameters
        if name == '@query-param' && component_parameters.key?('name')
          component_parameters = component_parameters.merge(
            'name' => decode_form_component(component_parameters['name'])
          )
        end

        StructuredFields.serialize_component(name, component_parameters)
      end

      def parse_configured_component(component)
        parsed = StructuredFields.parse_dictionary("sig=(#{component})")
        items = parsed.fetch('sig').first.first
        raise ArgumentError, 'expected one component' unless items.length == 1

        items.first
      end

      def canonical_parameters(parameters)
        raise ArgumentError, 'component parameters must be a Hash' unless parameters.is_a?(Hash)

        parameters.each_with_object({}) do |(key, value), normalized|
          normalized_key = key.to_s
          normalized[normalized_key] = normalized_key == 'name' ? value.to_s : value
        end
      end

      def string_parameter(parameters, name, required: false)
        value = parameters[name]
        raise SignatureError, "#{name} parameter is required" if required && value.nil?
        return nil if value.nil?
        raise SignatureError, "#{name} parameter must be a string" unless value.is_a?(String)

        value
      end

      def integer_parameter(parameters, name, required: false)
        value = parameters[name]
        raise SignatureError, "#{name} parameter is required" if required && value.nil?
        return nil if value.nil?
        raise SignatureError, "#{name} parameter must be an integer" unless value.is_a?(Integer)

        value
      end

      def parse_dictionary(value)
        raise MalformedSignature if value.nil?

        StructuredFields.parse_dictionary(value.to_s)
      end

      def unauthorized
        [
          401,
          {
            'content-type' => CONTENT_TYPE,
            'content-length' => '0'
          },
          []
        ]
      end

      module StructuredFields
        ByteSequence = Struct.new(:value)

        module_function

        def parse_dictionary(input)
          Parser.new(input).parse_dictionary
        end

        def strict_base64_decode(value)
          raise MalformedSignature, 'invalid structured field byte sequence' if value.empty?
          raise MalformedSignature, 'invalid structured field byte sequence' unless value.match?(/\A[A-Za-z0-9+\/]+(={1,2})?\z/)
          raise MalformedSignature, 'invalid structured field byte sequence' unless (value.length % 4).zero?
          raise MalformedSignature, 'invalid structured field byte sequence' if value.include?('=') && !value.match?(/=+\z/)

          value.unpack1('m0')
        rescue ArgumentError
          raise MalformedSignature, 'invalid structured field byte sequence'
        end

        def serialize_string(value)
          raise MalformedSignature, 'structured field string must be a String' unless value.is_a?(String)

          result = String.new('"')
          value.b.each_byte do |byte|
            raise MalformedSignature, 'invalid structured field string' if byte < 0x20 || byte > 0x7e

            character = byte.chr
            character = "\\#{character}" if character == '"' || character == '\\'
            result << character
          end
          result << '"'
          result
        end

        def serialize_component(name, parameters)
          raise MalformedSignature, 'component name must be a String' unless name.is_a?(String)

          result = serialize_string(name)
          parameters.sort.each do |key, value|
            result << ";#{key}="
            result << serialize_value(value)
          end
          result
        end

        def serialize_inner_list(items, parameters)
          result = String.new('(')
          result << items.map { |name, item_parameters| serialize_component(name, item_parameters) }.join(' ')
          result << ')'
          result << serialize_parameters(parameters)
          result
        end

        def serialize_parameters(parameters)
          parameters.each_with_object(String.new) do |(key, value), result|
            if value == true
              result << ";#{key}"
            else
              result << ";#{key}="
              result << serialize_value(value)
            end
          end
        end

        def serialize_value(value)
          case value
          when String then serialize_string(value)
          when Integer then value.to_s
          when true then '?1'
          when false then '?0'
          else raise MalformedSignature, 'unsupported structured field value'
          end
        end

        class Parser
          KEY_CHARACTERS = /[a-z0-9_\-.*]/.freeze
          TOKEN_CHARACTERS = /[a-zA-Z0-9_!#$%&'*+\-.^`|~:\/]/.freeze
          BASE64_CHARACTERS = /[A-Za-z0-9+\/=]/.freeze

          def initialize(input)
            @input = input.to_s
            @position = 0
          end

          def parse_dictionary
            dictionary = {}
            skip_spaces

            until end?
              key = parse_key
              has_value = consume('=')
              value = has_value && peek == '(' ? parse_inner_list : (has_value ? parse_bare_item : true)
              parameters = parse_parameters
              raise MalformedSignature, 'duplicate structured field key' if dictionary.key?(key)

              dictionary[key] = [value, parameters]
              skip_spaces
              break if end?

              consume!(',')
              skip_spaces
              raise MalformedSignature, 'unexpected structured field data' if end?
            end

            skip_spaces
            raise MalformedSignature, 'unexpected structured field data' unless end?

            dictionary
          end

          private

          def parse_inner_list
            consume!('(')
            items = []
            skip_spaces

            if peek == ')'
              consume!(')')
            else
              until peek == ')'
                raise MalformedSignature, 'unexpected end of structured field inner list' if end?

                item = parse_bare_item
                parameters = parse_parameters
                items << [item, parameters]
                break if peek == ')'

                skip_spaces
                raise MalformedSignature, 'unexpected end of structured field inner list' if end?
              end
              consume!(')')
            end

            parameters = parse_parameters
            [items, parameters]
          end

          def parse_parameters
            parameters = {}

            while peek == ';'
              position = @position
              advance
              skip_spaces
              begin
                key = parse_key
              rescue MalformedSignature
                @position = position
                break
              end

              value = if consume('=')
                parse_bare_item
              else
                true
              end
              raise MalformedSignature, 'duplicate structured field parameter' if parameters.key?(key)

              parameters[key] = value
            end

            parameters
          end

          def parse_bare_item
            case peek
            when '"' then parse_string
            when ':' then parse_byte_sequence
            when '?' then parse_boolean
            when '-', /[0-9]/ then parse_integer
            when /[a-zA-Z*]/ then parse_token
            else raise MalformedSignature, 'invalid structured field item'
            end
          end

          def parse_string
            consume!('"')
            value = String.new

            until peek == '"'
              raise MalformedSignature, 'unterminated structured field string' if end?

              character = advance
              if character == '\\'
                raise MalformedSignature, 'invalid structured field escape' if end?

                escaped = advance
                raise MalformedSignature, 'invalid structured field escape' unless escaped == '"' || escaped == '\\'

                character = escaped
              end
              byte = character.ord
              raise MalformedSignature, 'invalid structured field string' if byte < 0x20 || byte > 0x7e

              value << character
            end

            consume!('"')
            value
          end

          def parse_byte_sequence
            consume!(':')
            value = consume_while(BASE64_CHARACTERS)
            consume!(':')

            ByteSequence.new(StructuredFields.strict_base64_decode(value))
          end

          def parse_boolean
            consume!('?')
            case advance
            when '1' then true
            when '0' then false
            else raise MalformedSignature, 'invalid structured field boolean'
            end
          end

          def parse_integer
            start = @position
            negative = consume('-')
            digits = consume_while(/[0-9]/)
            raise MalformedSignature, 'invalid structured field integer' if digits.empty? || digits.length > 15
            raise MalformedSignature, 'invalid structured field integer leading zero' if digits.length > 1 && digits.start_with?('0')
            raise MalformedSignature, 'invalid structured field integer' if negative && digits == '0'

            @input[start...@position].to_i
          end

          def parse_token
            first = advance
            raise MalformedSignature, 'invalid structured field token' unless first.match?(/[a-zA-Z*]/)

            first + consume_while(TOKEN_CHARACTERS)
          end

          def parse_key
            key = consume_while(KEY_CHARACTERS)
            raise MalformedSignature, 'invalid structured field key' if key.empty? || !key.start_with?(/[a-z*]/)

            key
          end

          def consume_while(pattern)
            value = String.new
            while !end? && peek.match?(pattern)
              value << advance
            end
            value
          end

          def skip_spaces
            advance while peek == ' ' || peek == "\t"
          end

          def peek
            end? ? nil : @input[@position]
          end

          def consume(character)
            return false unless peek == character

            advance
            true
          end

          def consume!(character)
            raise MalformedSignature, "expected #{character}" unless consume(character)
          end

          def advance
            character = @input[@position]
            @position += 1
            character
          end

          def end?
            @position >= @input.length
          end
        end
      end
    end
  end
end
