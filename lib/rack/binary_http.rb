# frozen_string_literal: true

require 'stringio'

require_relative 'utils'

module Rack
  # Rack::BinaryHTTP encodes and decodes HTTP messages using the Binary
  # Representation of HTTP Messages (RFC 9292). It supports both the
  # known-length and indeterminate-length message formats for requests and
  # responses, including informational (1xx) responses, field sections,
  # chunked content, trailers, elided empty sections, and zero padding.
  #
  # Decoding is streaming: message content is exposed as an IO-like object
  # that pulls from the underlying source on demand, so a body is never
  # buffered in memory in its entirety. The source only needs to respond to
  # +readpartial+ (or +read+) and may return just a few bytes at a time.
  #
  # Three distinct failure modes are reported:
  #
  # * TruncatedMessage - the source ended in the middle of a structure.
  # * InvalidMessage - structurally complete but semantically invalid data.
  # * MessageTooLarge - a configured size limit was exceeded.
  module BinaryHTTP
    # Base class for all BinaryHTTP errors.
    class Error < StandardError; end

    # The input ended before the message was complete.
    class TruncatedMessage < Error; end

    # The message contained invalid control data.
    class InvalidMessage < Error; end

    # A configured length or count limit was exceeded.
    class MessageTooLarge < Error; end

    # Framing indicators (RFC 9292, Section 3).
    FRAME_REQUEST_KNOWN_LENGTH = 0x00
    FRAME_REQUEST_INDETERMINATE_LENGTH = 0x01
    FRAME_RESPONSE_KNOWN_LENGTH = 0x02
    FRAME_RESPONSE_INDETERMINATE_LENGTH = 0x03

    VARINT_MAX = (1 << 62) - 1

    # Default decoder limits. +content_length+ of nil means unlimited
    # (content is streamed, so a declared length never allocates memory).
    DEFAULT_LIMITS = {
      field_section_size: 1 << 20, # max bytes in a single field section
      fields: 100,                 # max fields in a single field section
      content_length: nil,         # max declared/observed content bytes
    }.freeze

    TOKEN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/
    FIELD_NAME = /\A[!#$%&'*+\-.^_`|~0-9a-z]+\z/
    SCHEME = /\A[a-z][a-z0-9+.-]*\z/
    FIELD_VALUE = /\A[^\x00\r\n]*\z/

    # Wraps a source IO and provides exact-length reads. The source may
    # return any number of bytes per call; short reads are retried.
    class ByteReader
      CHUNK_SIZE = 16 * 1024

      def initialize(io)
        @io = io
        @buffer = String.new(encoding: Encoding::BINARY)
        @offset = 0
        @eof = false
      end

      # Read exactly +count+ bytes or raise TruncatedMessage.
      def read_bytes(count)
        fill(count)
        result = @buffer.byteslice(@offset, count)
        @offset += count
        compact
        result
      end

      # Read a QUIC variable-length integer. With +allow_eof+, returns nil
      # when the source is cleanly exhausted at this boundary; a partial
      # integer still raises TruncatedMessage.
      def read_varint(allow_eof: false)
        if allow_eof
          return nil unless fill_optional(1)
        else
          fill(1)
        end
        first = @buffer.getbyte(@offset)
        length = 1 << (first >> 6)
        fill(length)
        value = first & 0x3f
        (length - 1).times do |i|
          value = (value << 8) | @buffer.getbyte(@offset + 1 + i)
        end
        @offset += length
        compact
        value
      end

      # True when no more bytes are available. May read from the source.
      def eof?
        !fill_optional(1)
      end

      private

      def fill(count)
        return if @buffer.bytesize - @offset >= count
        unless fill_optional(count)
          raise TruncatedMessage,
            "input ended with #{count - (@buffer.bytesize - @offset)} bytes still expected"
        end
      end

      def fill_optional(count)
        while @buffer.bytesize - @offset < count && !@eof
          begin
            data = read_some
          rescue EOFError
            @eof = true
            break
          end
          if data.nil? || data.empty?
            @eof = true
            break
          end
          @buffer << data.b
        end
        @buffer.bytesize - @offset >= count
      end

      def read_some
        if @io.respond_to?(:readpartial)
          @io.readpartial(CHUNK_SIZE)
        else
          @io.read(CHUNK_SIZE)
        end
      end

      def compact
        return if @offset == 0
        if @offset == @buffer.bytesize
          @buffer.clear
        elsif @offset >= CHUNK_SIZE
          @buffer = @buffer.byteslice(@offset, @buffer.bytesize - @offset)
        else
          return
        end
        @offset = 0
      end
    end

    class << self
      # Encode an integer as a QUIC variable-length integer (RFC 9000,
      # Section 16).
      def encode_varint(value)
        value = Integer(value)
        if value < 0 || value > VARINT_MAX
          raise ArgumentError, "value #{value} cannot be encoded as a varint"
        end
        if value < 0x40
          [value].pack("C")
        elsif value < 0x4000
          [value | 0x4000].pack("S>")
        elsif value < 0x40000000
          [value | 0x80000000].pack("L>")
        else
          [value | 0xC000000000000000].pack("Q>")
        end
      end

      # Decode a varint from +data+ starting at +pos+. Returns
      # [value, new_pos] or raises InvalidMessage when the bytes run out.
      def decode_varint(data, pos)
        first = data.getbyte(pos)
        raise InvalidMessage, "truncated varint" if first.nil?
        length = 1 << (first >> 6)
        value = first & 0x3f
        (length - 1).times do |i|
          byte = data.getbyte(pos + 1 + i)
          raise InvalidMessage, "truncated varint" if byte.nil?
          value = (value << 8) | byte
        end
        [value, pos + length]
      end
    end

    # IO-like streaming reader over the content of a single message.
    # Satisfies the Rack input stream contract (+gets+, +each+, +read+,
    # +close+). Trailers are parsed from the underlying source lazily,
    # once the content is fully consumed.
    class ContentReader
      include Enumerable

      def initialize(reader, length:, limit: nil, on_complete: nil)
        @reader = reader
        @remaining = length # nil for indeterminate-length content
        @chunk_remaining = 0
        @received = 0
        @limit = limit
        @on_complete = on_complete
        @done = false
        @closed = false
        @gets_buffer = nil
      end

      # IO#read compatible. Without a length, reads until EOF; with a
      # length, reads at most that many bytes, returning nil at EOF.
      def read(length = nil, buffer = nil)
        raise IOError, "closed stream" if @closed
        raise ArgumentError, "negative length #{length}" if length && length < 0

        if length.nil?
          data = String.new(encoding: Encoding::BINARY)
          while (chunk = read_chunk)
            data << chunk
          end
        elsif length == 0
          data = String.new(encoding: Encoding::BINARY)
        else
          data = read_chunk(length)
          return nil if data.nil?
        end

        if buffer
          buffer.replace(data)
        else
          data
        end
      end

      def gets(separator = $/)
        raise IOError, "closed stream" if @closed
        @gets_buffer ||= String.new(encoding: Encoding::BINARY)
        loop do
          if (index = @gets_buffer.index(separator))
            return @gets_buffer.slice!(0, index + separator.bytesize)
          end
          chunk = read_chunk
          if chunk.nil?
            return nil if @gets_buffer.empty?
            return @gets_buffer.slice!(0, @gets_buffer.bytesize)
          end
          @gets_buffer << chunk
        end
      end

      def each
        return enum_for(:each) unless block_given?
        while (chunk = read_chunk)
          yield chunk
        end
      end

      def eof?
        @done || @closed
      end

      # Discard any remaining content.
      def drain
        each { |_| }
        nil
      end

      def close
        @closed = true
        nil
      end

      private

      # Returns the next piece of content (up to +max+ bytes), or nil at
      # the end of the content. Finalizes the message (trailers, padding
      # checks) exactly once when the content is exhausted.
      def read_chunk(max = ByteReader::CHUNK_SIZE)
        return nil if @done || @closed

        if @remaining
          return finish if @remaining == 0
          want = [max, @remaining].min
          data = @reader.read_bytes(want)
          @remaining -= data.bytesize
        else
          if @chunk_remaining == 0
            length = @reader.read_varint
            return finish if length == 0
            @chunk_remaining = length
          end
          want = [max, @chunk_remaining].min
          data = @reader.read_bytes(want)
          @chunk_remaining -= data.bytesize
        end

        @received += data.bytesize
        if @limit && @received > @limit
          raise MessageTooLarge,
            "content exceeds limit of #{@limit} bytes"
        end
        data
      end

      def finish
        @done = true
        @on_complete&.call
        nil
      end
    end

    # Common base for decoded messages.
    class Message
      # Array of [name, value] header pairs, in wire order.
      attr_reader :headers

      # A ContentReader over the message content.
      attr_accessor :body

      def initialize(headers)
        @headers = headers
        @trailers = nil
      end

      # Array of [name, value] trailer pairs. Reading the trailers forces
      # any unread content to be consumed first.
      def trailers
        @body.drain if @trailers.nil? && @body
        @trailers || []
      end

      # @api private
      def trailers=(fields)
        @trailers = fields
      end

      def request?
        is_a?(RequestMessage)
      end

      def response?
        is_a?(ResponseMessage)
      end
    end

    # A decoded request message.
    class RequestMessage < Message
      attr_reader :method, :scheme, :authority, :path

      def initialize(method:, scheme:, authority:, path:, headers:)
        super(headers)
        @method = method
        @scheme = scheme
        @authority = authority
        @path = path
      end
    end

    # A decoded response message.
    class ResponseMessage < Message
      # The final (non-1xx) status code.
      attr_reader :status

      # Array of [status, headers] pairs for informational responses.
      attr_reader :informational

      def initialize(status:, headers:, informational:)
        super(headers)
        @status = status
        @informational = informational
      end
    end

    # Incrementally decodes a sequence of binary HTTP messages from a
    # source IO. Use #next_message or #each.
    class Decoder
      include Enumerable

      # Create a decoder reading from +io+ (anything responding to
      # +readpartial+ or +read+; a String is wrapped automatically).
      #
      # Options:
      # * +limits+: hash overriding DEFAULT_LIMITS.
      # * +padding+: when true, zero-valued octets between messages are
      #   discarded as padding (RFC 9292, Section 3). Do not enable when
      #   known-length requests (framing indicator 0x00) can follow.
      def initialize(io, limits: {}, padding: false)
        io = StringIO.new(io) if io.is_a?(String)
        @reader = ByteReader.new(io)
        @limits = DEFAULT_LIMITS.merge(limits)
        @padding = padding
        @current = nil
        @single = false
      end

      # Decode the next message, or return nil at end of input. Any
      # unread content of the previous message is discarded first.
      def next_message
        @current&.body&.drain
        indicator = read_indicator
        return nil if indicator.nil?
        @current = decode_message(indicator)
      end

      def each
        return enum_for(:each) unless block_given?
        while (message = next_message)
          yield message
        end
      end

      # @api private
      # Require the decoded message to be the only content of the source:
      # after it, only zero-valued padding octets may follow.
      def expect_single_message!
        @single = true
      end

      # @api private
      # Called by ContentReader when a message's content is exhausted.
      def content_completed
        return unless @single
        until @reader.eof?
          byte = @reader.read_bytes(1)
          unless byte == "\x00"
            raise InvalidMessage, "unexpected data after end of message"
          end
        end
      end

      private

      def read_indicator
        loop do
          indicator = @reader.read_varint(allow_eof: true)
          return nil if indicator.nil?
          next if @padding && indicator == 0
          return indicator
        end
      end

      def decode_message(indicator)
        case indicator
        when FRAME_REQUEST_KNOWN_LENGTH
          decode_request_message(false)
        when FRAME_REQUEST_INDETERMINATE_LENGTH
          decode_request_message(true)
        when FRAME_RESPONSE_KNOWN_LENGTH
          decode_response_message(false)
        when FRAME_RESPONSE_INDETERMINATE_LENGTH
          decode_response_message(true)
        else
          raise InvalidMessage, "unknown framing indicator #{indicator}"
        end
      end

      def decode_request_message(indeterminate)
        method = read_control_string("method")
        unless method.match?(TOKEN)
          raise InvalidMessage, "invalid request method #{method.inspect}"
        end
        scheme = read_control_string("scheme")
        unless scheme.match?(SCHEME)
          raise InvalidMessage, "invalid request scheme #{scheme.inspect}"
        end
        authority = read_control_string("authority")
        path = read_control_string("path")
        headers = read_field_section(indeterminate)
        message = RequestMessage.new(
          method: method, scheme: scheme, authority: authority,
          path: path, headers: headers)
        attach_content(message, indeterminate)
        message
      end

      def decode_response_message(indeterminate)
        informational = []
        status = nil
        loop do
          status = @reader.read_varint
          if status < 100 || status > 999
            raise InvalidMessage, "invalid response status #{status}"
          end
          break if status >= 200
          informational << [status, read_field_section(indeterminate)]
        end
        headers = read_field_section(indeterminate)
        message = ResponseMessage.new(
          status: status, headers: headers, informational: informational)
        attach_content(message, indeterminate)
        message
      end

      # RFC 9292, Section 3.1: a known-length message may end after its
      # header section or content, in which case the remaining sections
      # are empty.
      def attach_content(message, indeterminate)
        if indeterminate
          message.body = ContentReader.new(
            @reader, length: nil, limit: @limits[:content_length],
            on_complete: -> { complete_message(message, true) })
        else
          length = @reader.read_varint(allow_eof: true)
          if length.nil?
            message.body = ContentReader.new(
              @reader, length: 0,
              on_complete: -> { content_completed })
            message.trailers = []
          else
            check_length("content", length, @limits[:content_length])
            message.body = ContentReader.new(
              @reader, length: length, limit: @limits[:content_length],
              on_complete: -> { complete_message(message, false) })
          end
        end
      end

      def complete_message(message, indeterminate)
        message.trailers = read_trailers(indeterminate)
        content_completed
      end

      def read_trailers(indeterminate)
        if indeterminate
          read_field_section(true)
        else
          length = @reader.read_varint(allow_eof: true)
          return [] if length.nil?
          parse_field_section(read_section_data(length))
        end
      end

      def read_control_string(what)
        length = @reader.read_varint
        check_length(what, length, @limits[:field_section_size])
        @reader.read_bytes(length)
      end

      def read_field_section(indeterminate)
        if indeterminate
          fields = []
          received = 0
          loop do
            name_length = @reader.read_varint
            break if name_length == 0
            received += read_field_line(fields, name_length)
            check_length("field section", received,
              @limits[:field_section_size])
          end
          check_field_count(fields)
          fields
        else
          parse_field_section(read_section_data(@reader.read_varint))
        end
      end

      def read_section_data(length)
        check_length("field section", length, @limits[:field_section_size])
        @reader.read_bytes(length)
      end

      def parse_field_section(data)
        fields = []
        pos = 0
        while pos < data.bytesize
          name_length, pos = BinaryHTTP.decode_varint(data, pos)
          name, pos = take(data, pos, name_length)
          value_length, pos = BinaryHTTP.decode_varint(data, pos)
          value, pos = take(data, pos, value_length)
          fields << validate_field(name, value)
        end
        check_field_count(fields)
        fields
      end

      # Reads one field line with a known name length from the stream.
      # Returns the number of content bytes consumed.
      def read_field_line(fields, name_length)
        name = @reader.read_bytes(name_length)
        value_length = @reader.read_varint
        value = @reader.read_bytes(value_length)
        fields << validate_field(name, value)
        name_length + value_length
      end

      def validate_field(name, value)
        if name.empty?
          raise InvalidMessage, "field line with empty name"
        end
        unless name.match?(FIELD_NAME)
          raise InvalidMessage, "invalid field name #{name.inspect}"
        end
        unless value.match?(FIELD_VALUE)
          raise InvalidMessage, "invalid field value for #{name.inspect}"
        end
        [name, value]
      end

      def take(data, pos, length)
        result = data.byteslice(pos, length)
        if result.nil? || result.bytesize != length
          raise InvalidMessage, "field section extends past its end"
        end
        [result, pos + length]
      end

      def check_length(what, length, limit)
        if limit && length > limit
          raise MessageTooLarge,
            "#{what} of #{length} bytes exceeds limit of #{limit}"
        end
      end

      def check_field_count(fields)
        limit = @limits[:fields]
        if limit && fields.size > limit
          raise MessageTooLarge,
            "field section has #{fields.size} fields, limit is #{limit}"
        end
      end
    end

    class << self
      # Encode a request message. Returns a String, unless +body+ is an
      # Enumerable, in which case a lazy Enumerator of encoded chunks is
      # returned (requires +indeterminate: true+).
      #
      # +headers+ and +trailers+ are Hashes or Arrays of [name, value]
      # pairs. +padding+ appends that many zero octets.
      def encode_request(method:, scheme: "https", authority: "", path: "/",
                         headers: [], body: nil, trailers: [],
                         indeterminate: false,
                         chunk_size: ByteReader::CHUNK_SIZE, padding: 0)
        head = String.new(encoding: Encoding::BINARY)
        head << encode_varint(indeterminate ?
          FRAME_REQUEST_INDETERMINATE_LENGTH : FRAME_REQUEST_KNOWN_LENGTH)
        head << encode_length_prefixed(method.to_s)
        head << encode_length_prefixed(scheme.to_s)
        head << encode_length_prefixed(authority.to_s)
        head << encode_length_prefixed(path.to_s)
        head << encode_field_section(headers, indeterminate)
        tail = encode_field_section(trailers, indeterminate)
        tail << "\x00".b * padding
        encode_message(head, body, tail, indeterminate, chunk_size)
      end

      # Encode a response message. +informational+ is an Array of
      # [status, headers] pairs for 1xx responses preceding the final
      # response. See ::encode_request for the return value.
      def encode_response(status:, headers: [], body: nil, informational: [],
                          trailers: [], indeterminate: false,
                          chunk_size: ByteReader::CHUNK_SIZE, padding: 0)
        informational.each do |info_status, _|
          unless info_status >= 100 && info_status < 200
            raise ArgumentError,
              "informational status must be 1xx, got #{info_status}"
          end
        end
        unless status >= 200 && status <= 999
          raise ArgumentError, "final status must be 200..999, got #{status}"
        end

        head = String.new(encoding: Encoding::BINARY)
        head << encode_varint(indeterminate ?
          FRAME_RESPONSE_INDETERMINATE_LENGTH : FRAME_RESPONSE_KNOWN_LENGTH)
        informational.each do |info_status, info_headers|
          head << encode_varint(info_status)
          head << encode_field_section(info_headers, indeterminate)
        end
        head << encode_varint(status)
        head << encode_field_section(headers, indeterminate)
        tail = encode_field_section(trailers, indeterminate)
        tail << "\x00".b * padding
        encode_message(head, body, tail, indeterminate, chunk_size)
      end

      # Decode a single request message from +io+. After the message,
      # only zero-valued padding octets may remain in the source.
      def decode_request(io, limits: {})
        decode_single(io, limits, :request)
      end

      # Decode a single response message from +io+.
      def decode_response(io, limits: {})
        decode_single(io, limits, :response)
      end

      # Build a Rack environment hash from a decoded request message.
      # The message body becomes +rack.input+ without buffering.
      def rack_env(message, errors: $stderr)
        unless message.is_a?(RequestMessage)
          raise ArgumentError, "expected a RequestMessage"
        end

        path, _, query = message.path.partition("?")
        server_name, server_port = split_authority(message)

        env = {
          "REQUEST_METHOD" => message.method,
          "SCRIPT_NAME" => "",
          "PATH_INFO" => Utils.unescape_path(path),
          "QUERY_STRING" => query,
          "SERVER_NAME" => server_name,
          "SERVER_PORT" => server_port,
          "HTTP_VERSION" => "HTTP/1.1",
          "rack.url_scheme" => message.scheme,
          "rack.input" => message.body,
          "rack.errors" => errors,
        }

        message.headers.each do |name, value|
          key = case name
                when "content-type" then "CONTENT_TYPE"
                when "content-length" then "CONTENT_LENGTH"
                else "HTTP_" + name.tr("-", "_").upcase
                end
          env[key] = env.key?(key) ? "#{env[key]}, #{value}" : value
        end
        env
      end

      # Convert a decoded response message into a Rack response triple
      # [status, headers, body]. The body streams from the source.
      def to_rack_response(message)
        unless message.is_a?(ResponseMessage)
          raise ArgumentError, "expected a ResponseMessage"
        end
        headers = {}
        message.headers.each do |name, value|
          if headers.key?(name)
            headers[name] = "#{headers[name]}, #{value}"
          else
            headers[name] = value
          end
        end
        [message.status, headers, message.body]
      end

      # Encode a Rack response triple as a binary HTTP response. When the
      # body is an Enumerable it is consumed lazily and the result is an
      # Enumerator (see ::encode_response).
      def from_rack_response(status, headers, body, **options)
        encode_response(status: status, headers: headers.to_a, body: body,
          **options)
      end

      # Encode a Rack environment hash as a binary HTTP request. With
      # +indeterminate: true+ the rack.input body is streamed; otherwise
      # it is buffered so its length is known up front.
      def from_rack_env(env, indeterminate: false, **options)
        headers = []
        env.each do |key, value|
          next unless value.is_a?(String)
          if key.start_with?("HTTP_")
            headers << [key[5..].tr("_", "-").downcase, value]
          elsif key == "CONTENT_TYPE"
            headers << ["content-type", value]
          elsif key == "CONTENT_LENGTH"
            headers << ["content-length", value]
          end
        end

        authority = env["HTTP_HOST"] ||
          "#{env['SERVER_NAME']}#{":#{env['SERVER_PORT']}" if env['SERVER_PORT']}"

        path = +"#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
        query = env["QUERY_STRING"]
        path << "?#{query}" unless query.nil? || query.empty?

        body = rack_input_body(env["rack.input"], indeterminate)

        encode_request(
          method: env["REQUEST_METHOD"] || "GET",
          scheme: env["rack.url_scheme"] || "http",
          authority: authority, path: path,
          headers: headers, body: body,
          indeterminate: indeterminate, **options)
      end

      private

      def encode_length_prefixed(string)
        string = string.b
        encode_varint(string.bytesize) << string
      end

      def encode_field_section(fields, indeterminate)
        fields = fields.to_a if fields.is_a?(Hash)
        out = String.new(encoding: Encoding::BINARY)
        fields.each do |name, value|
          name = name.to_s.downcase
          unless name.match?(FIELD_NAME)
            raise ArgumentError, "invalid field name #{name.inspect}"
          end
          value = value.to_s
          unless value.match?(FIELD_VALUE)
            raise ArgumentError, "invalid field value for #{name.inspect}"
          end
          out << encode_length_prefixed(name)
          out << encode_length_prefixed(value)
        end
        if indeterminate
          out << "\x00".b
        else
          out = encode_varint(out.bytesize) << out
        end
        out
      end

      def encode_message(head, body, tail, indeterminate, chunk_size)
        if body.respond_to?(:each) && !body.is_a?(String)
          unless indeterminate
            raise ArgumentError,
              "Enumerable bodies require indeterminate: true"
          end
          return encode_streaming(head, body, tail, chunk_size)
        end

        out = head
        if indeterminate
          encode_chunks(out, body ? [body] : [], chunk_size)
        else
          body = body ? body.b : ""
          out << encode_length_prefixed(body)
        end
        out << tail
      end

      def encode_streaming(head, body, tail, chunk_size)
        Enumerator.new do |yielder|
          begin
            yielder << head
            body.each do |part|
              part = part.to_s.b
              offset = 0
              while offset < part.bytesize
                piece = part.byteslice(offset, chunk_size)
                yielder << encode_length_prefixed(piece)
                offset += piece.bytesize
              end
            end
            yielder << "\x00".b
            yielder << tail
          ensure
            body.close if body.respond_to?(:close)
          end
        end
      end

      def encode_chunks(out, parts, chunk_size)
        parts.each do |part|
          part = part.b
          offset = 0
          while offset < part.bytesize
            piece = part.byteslice(offset, chunk_size)
            out << encode_length_prefixed(piece)
            offset += piece.bytesize
          end
        end
        out << "\x00".b
      end

      def rack_input_body(input, indeterminate)
        return nil unless input
        if indeterminate
          Enumerator.new do |yielder|
            while (chunk = input.read(ByteReader::CHUNK_SIZE))
              yielder << chunk
            end
          end
        else
          data = input.read
          data && !data.empty? ? data : nil
        end
      end

      def split_authority(message)
        authority = message.authority
        return ["", default_port(message.scheme)] if authority.empty?
        if authority.start_with?("[")
          host, _, rest = authority[1..].partition("]")
          port = rest.start_with?(":") ? rest[1..] : nil
        else
          host, _, port = authority.rpartition(":")
          if host.empty?
            host, port = authority, nil
          end
        end
        [host, (port.nil? || port.empty?) ? default_port(message.scheme) : port]
      end

      def default_port(scheme)
        case scheme
        when "http" then "80"
        when "https" then "443"
        else ""
        end
      end

      def decode_single(io, limits, type)
        decoder = Decoder.new(io, limits: limits)
        decoder.expect_single_message!
        message = decoder.next_message
        raise TruncatedMessage, "no message in input" if message.nil?
        expected = type == :request ? RequestMessage : ResponseMessage
        unless message.is_a?(expected)
          raise InvalidMessage, "expected a #{type} message"
        end
        message
      end
    end
  end
end
