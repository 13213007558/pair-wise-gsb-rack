# frozen_string_literal: true

require 'stringio'

module Rack
  # Binary HTTP encoding and decoding as specified by RFC 9292.
  module BinaryHTTP
    class Error < StandardError; end
    class ParseError < Error; end
    class TruncatedError < Error; end
    class LengthError < Error; end
    class ControlDataError < Error; end

    DEFAULT_MAX_LENGTH = 1 << 20

    KNOWN_REQUEST = 0
    KNOWN_INTERIM_RESPONSE = 1
    KNOWN_FINAL_RESPONSE = 2
    KNOWN_FIELDS = 3
    KNOWN_TRAILERS = 4
    KNOWN_CONTENT = 5
    KNOWN_PADDING = 6
    INDETERMINATE_REQUEST = 7
    INDETERMINATE_INTERIM_RESPONSE = 8
    INDETERMINATE_FINAL_RESPONSE = 9
    INDETERMINATE_FIELDS = 10
    INDETERMINATE_TRAILERS = 11
    INDETERMINATE_CONTENT = 12
    INDETERMINATE_PADDING = 13

    BINARY = Encoding::BINARY
    private_constant :BINARY

    def self.binary(data)
      data.to_s.b
    end

    module Varint
      module_function

      def encode(value, output)
        value = validate(value)
        if value < 2**6
          output << value.chr(BINARY)
        elsif value < 2**14
          output << [0x80 | ((value >> 8) & 0x3f), value & 0xff].pack("C2")
        elsif value < 2**30
          output << [0xc0 | (value >> 24), (value >> 16) & 0xff,
                     (value >> 8) & 0xff, value & 0xff].pack("C4")
        else
          high = value >> 32
          low = value & 0xffffffff
          output << [0xe0 | (high >> 24), (high >> 16) & 0xff,
                     (high >> 8) & 0xff, high & 0xff,
                     (low >> 24) & 0xff, (low >> 16) & 0xff,
                     (low >> 8) & 0xff, low & 0xff].pack("C8")
        end
      end

      def read(input, max_length: nil)
        first = input.readbyte
        raise TruncatedError, "truncated variable-length integer" if first.nil?
        return decode_integer(first, String.new(encoding: BINARY), max_length: max_length) if first < 0x80

        size = if first < 0xc0
          2
        elsif first < 0xe0
          4
        else
          8
        end
        rest = input.read_exact(size - 1)
        raise TruncatedError, "truncated variable-length integer" if rest.nil? || rest.bytesize != size - 1
        decode_integer(first, rest, max_length: max_length)
      end

      def decode_integer(first, rest, max_length: nil)
        size = rest.bytesize + 1
        value = first & (size == 2 ? 0x3f : size == 1 ? 0x7f : 0x1f)
        rest.each_byte { |byte| value = (value << 8) | byte }
        minimum = size == 1 ? 0 : size == 2 ? 2**6 : size == 4 ? 2**14 : 2**30
        raise ParseError, "non-canonical variable-length integer" if value < minimum
        raise ParseError, "variable-length integer exceeds 62-bit range" if value >= 2**62
        if max_length && value > max_length
          raise LengthError, "declared length #{value} exceeds limit #{max_length}"
        end
        value
      end

      def validate(value)
        unless value.is_a?(Integer) && value >= 0 && value < 2**62
          raise ArgumentError, "variable-length integer must be an unsigned 62-bit value"
        end
        value
      end
    end

    class IOReader
      def initialize(io, max_length: DEFAULT_MAX_LENGTH)
        @io = io
        @max_length = max_length
        @pushback = nil
      end

      def readbyte
        if @pushback
          byte = @pushback
          @pushback = nil
          byte
        else
          byte = @io.getbyte
          raise TruncatedError, "unexpected end of Binary HTTP message" if byte.nil?
          byte
        end
      end

      def ungetbyte(byte)
        raise ParseError, "only one byte can be pushed back" unless @pushback.nil?
        @pushback = byte
      end

      def read_exact(length, max_length: @max_length)
        check_length(length, max_length)
        result = String.new(encoding: BINARY)
        while result.bytesize < length
          chunk = @io.read(length - result.bytesize)
          if chunk.nil? || chunk.empty?
            raise TruncatedError, "unexpected end of Binary HTTP message"
          end
          result << chunk.b
        end
        result
      end

      def varint(max_length: @max_length)
        Varint.read(self, max_length: max_length)
      end

      def eof?
        return false unless @pushback.nil?
        @io.eof?
      rescue IOError, SystemCallError
        false
      end

      private

      def check_length(length, max_length)
        if !length.is_a?(Integer) || length.negative?
          raise ParseError, "length must be a non-negative integer"
        end
        return unless max_length && length > max_length
        raise LengthError, "declared length #{length} exceeds limit #{max_length}"
      end
    end

    class BoundedReader
      attr_accessor :remaining

      def initialize(source, remaining, max_length: DEFAULT_MAX_LENGTH)
        @source = source
        @remaining = remaining
        @max_length = max_length
      end

      def readbyte
        return nil if @remaining.zero?
        byte = @source.readbyte
        @remaining -= 1
        byte
      rescue TruncatedError
        raise TruncatedError, "known-length frame ended unexpectedly"
      end

      def read(length = nil)
        return drain if length.nil?
        return String.new(encoding: BINARY) if length.zero?
        return nil if @remaining.zero?
        data = @source.read_exact([length, @remaining].min, max_length: nil)
        @remaining -= data.bytesize
        data
      end

      def read_exact(length, max_length: @max_length)
        raise LengthError if max_length && length > max_length
        if length > @remaining
          raise TruncatedError, "known-length frame ended unexpectedly"
        end
        data = @source.read_exact(length, max_length: nil)
        @remaining -= length
        data
      end

      def varint(max_length: @max_length)
        Varint.read(self, max_length: max_length)
      end

      def ungetbyte(byte)
        @source.ungetbyte(byte)
        @remaining += 1
      end

      def eof?
        @remaining.zero?
      end

      def finish!
        unless @remaining.zero?
          raise ParseError, "known-length frame contains trailing bytes"
        end
      end

      private

      def drain
        return String.new(encoding: BINARY) if @remaining.zero?
        data = @source.read_exact(@remaining, max_length: nil)
        @remaining = 0
        data
      end
    end

    class ChunkedReader
      def initialize(source)
        @source = source
        @remaining = 0
        @finished = false
      end

      def read(length = nil)
        prepare! if @remaining.zero? && !@finished
        return nil if @finished
        amount = [length || 16 * 1024, @remaining].min
        data = read_exact(amount)
        data
      end

      def readbyte
        prepare! if @remaining.zero? && !@finished
        return nil if @finished
        byte = frame_source.readbyte
        @remaining -= 1
        byte
      end

      def read_exact(length, max_length: nil)
        data = String.new(encoding: BINARY)
        while data.bytesize < length
          prepare! if @remaining.zero? && !@finished
          break if @finished
          amount = [length - data.bytesize, @remaining].min
          data << frame_source.read_exact(amount, max_length: nil)
          @remaining -= amount
        end
        data
      rescue TruncatedError
        raise TruncatedError, "chunked content ended unexpectedly"
      end

      def varint(max_length: nil)
        Varint.read(self, max_length: max_length)
      end

      def ungetbyte(byte)
        frame_source.ungetbyte(byte)
        @remaining += 1
      end

      def eof?
        @finished
      end

      def finish!
        until @finished
          prepare!
          read_exact(@remaining) unless @remaining.zero?
        end
      end

      private

      def frame_source
        @source
      end

      def prepare!
        size = Varint.read(frame_source, max_length: nil)
        if size.zero?
          @remaining = 0
          @finished = true
        else
          @remaining = size
        end
      end
    end

    FieldLine = Struct.new(:name, :value)

    class BodyInput
      def initialize(message)
        @message = message
      end

      def read(length = nil, buffer = nil)
        data = @message.read_body(length)
        data ||= String.new(encoding: BINARY) if length.nil?
        buffer&.replace(data || String.new(encoding: BINARY))
        data
      end

      def gets
        @message.read_body(4096)
      end

      def each
        return enum_for(:each) unless block_given?
        loop do
          chunk = @message.read_body(16 * 1024)
          break if chunk.nil?
          yield chunk unless chunk.empty?
        end
      end

      def close
        @message.close
      end

      def external_encoding
        Encoding::ASCII_8BIT
      end

      def binmode?
        true
      end
    end

    class DecodedMessage
      attr_reader :headers, :informational, :trailers
      attr_accessor :status, :parser, :source, :bounded, :state, :body_reader

      def initialize
        @headers = []
        @informational = []
        @trailers = []
        @state = :headers
        @body_reader = nil
        @finished = false
      end

      def fields_hash(fields)
        fields.each_with_object({}) do |field, hash|
          if hash.key?(field.name)
            hash[field.name] = [hash[field.name], field.value].flatten
          else
            hash[field.name] = field.value
          end
        end
      end

      def headers_hash
        fields_hash(@headers)
      end

      def trailers_hash
        fields_hash(@trailers)
      end

      def read_body(length = nil)
        return read_all_body if length.nil?
        read_body_chunk(length)
      end

      def read_all_body
        result = String.new(encoding: BINARY)
        while (chunk = read_body_chunk(16 * 1024))
          result << chunk
        end
        result
      end

      def read_body_chunk(length)
        return nil if @finished
        data = read_from_body(length)
        if data.nil?
          @finished = true
          parser.finish_message(self)
        end
        data
      end

      def drain_body
        result = String.new(encoding: BINARY)
        while (chunk = read_body(16 * 1024))
          result << chunk
        end
        result
      end

      def read_trailers
        drain_body
        @trailers
      end

      def close
        @finished = true
        parser.finish_message(self)
      rescue Error
      end

      def each_body
        return enum_for(:each_body) unless block_given?
        while (chunk = read_body(16 * 1024))
          yield chunk unless chunk.empty?
        end
      end

      def read(length = nil)
        read_body(length)
      end

      def finish!
        @finished = true
      end

      private

      def read_from_body(length)
        loop do
          parser.advance(self)
          return nil if @finished
          next unless @body_reader
          data = @body_reader.read(length)
          if data.nil? || (length && length.positive? && data.empty?)
            @body_reader = nil
            self.state = :body_frames if state == :body_open
            next if length
          end
          if @body_reader.respond_to?(:eof?) && @body_reader.eof?
            self.state = :body_frames
          end
          return data
        end
      end
    end

    class DecodedRequest < DecodedMessage
      attr_accessor :method, :scheme, :authority, :path

      def to_rack_env(**options)
        RackAdapter.request_env(self, **options)
      end
    end

    class DecodedResponse < DecodedMessage
      def to_rack_response(**options)
        RackAdapter.response_tuple(self, **options)
      end
    end

    class MessageParser
      def initialize(io, max_length: DEFAULT_MAX_LENGTH)
        @reader = io.is_a?(IOReader) ? io : IOReader.new(io, max_length: max_length)
        @max_length = max_length
      end

      public

      def parse_request
        type = @reader.readbyte
        case type
        when KNOWN_REQUEST
          length = @reader.varint
          build_request(bounded(length), true)
        when INDETERMINATE_REQUEST
          build_request(@reader, false)
        else
          raise ParseError, "expected request framing type, got #{type}"
        end
      end

      def parse_response
        type = @reader.readbyte
        case type
        when KNOWN_INTERIM_RESPONSE, KNOWN_FINAL_RESPONSE
          length = @reader.varint
          build_response(bounded(length), type == KNOWN_INTERIM_RESPONSE, true)
        when INDETERMINATE_INTERIM_RESPONSE, INDETERMINATE_FINAL_RESPONSE
          build_response(@reader, type == INDETERMINATE_INTERIM_RESPONSE, false)
        else
          raise ParseError, "expected response framing type, got #{type}"
        end
      end

      def advance(message)
        return if message.state == :body_open && message.body_reader
        source = message.source
        case message.state
        when :complete
          finish_message(message)
        when :padding
          skip_padding(message)
        else
          return finish_message(message) if source.eof?
          type = source.readbyte
          parse_body_frame(message, type)
        end
      end

      def finish_message(message)
        return if message.state == :finished
        message.body_reader = nil
        message.finish!
        message.state = :finished
        message.source.finish! if message.bounded
      end

      private

      def bounded(length)
        BoundedReader.new(@reader, length, max_length: @max_length)
      end

      def build_request(source, bounded)
        message = DecodedRequest.new
        message.parser = self
        message.source = source
        message.bounded = bounded
        read_request_control(source, message)
        parse_header_section(message)
        message
      end

      def read_request_control(source, message)
        length = source.varint
        raw = source.read_exact(length)
        control = BoundedReader.new(IOReader.new(StringIO.new(raw)), length, max_length: @max_length)
        values = 4.times.map do
          size = control.varint
          control.read_exact(size)
        end
        control.finish!
        message.method, message.scheme, message.authority, message.path = values
        validate_request_control(message)
      rescue TruncatedError
        raise
      rescue ParseError
        raise ControlDataError, "invalid request control data"
      end

      def validate_request_control(message)
        [message.method, message.scheme, message.authority, message.path].each do |value|
          unless value.is_a?(String) && value.valid_encoding?
            raise ControlDataError, "request control strings must be valid UTF-8"
          end
        end
        unless message.method.match?(/\A[!-#$%&'*+\-.^_`|~0-9A-Za-z]+\z/)
          raise ControlDataError, "invalid request method"
        end
      end

      def build_response(source, interim, bounded)
        message = DecodedResponse.new
        message.parser = self
        message.source = source
        message.bounded = bounded
        consume_informational(message, source) unless interim
        message.status = read_status(source)
        parse_header_section(message)
        message
      end

      def consume_informational(message, source)
        loop do
          return if source.eof?
          type = source.readbyte
          if type == KNOWN_INTERIM_RESPONSE
            length = source.varint
            child_source, after_remaining = child_frame(source, length)
            nested = build_interim(child_source, true)
            source.remaining = after_remaining if source.is_a?(BoundedReader)
            add_informational(message, nested)
          elsif type == INDETERMINATE_INTERIM_RESPONSE
            nested = build_interim(source, source.is_a?(BoundedReader))
            add_informational(message, nested)
          else
            source.ungetbyte(type)
            return
          end
        end
      end

      def build_interim(source, bounded)
        message = DecodedResponse.new
        message.parser = self
        message.source = source
        message.bounded = bounded
        message.status = read_status(source)
        parse_header_section(message)
        message
      end

      def child_frame(source, length)
        return [bounded(length), nil] unless source.is_a?(BoundedReader)
        after_remaining = source.remaining - length
        raise TruncatedError, "known-length frame ended unexpectedly" if after_remaining.negative?
        child = BoundedReader.new(source, length, max_length: @max_length)
        [child, after_remaining]
      end



      def read_status(source)
        status = Varint.read(source, max_length: nil)
        unless status >= 100 && status <= 599
          raise ControlDataError, "invalid response status #{status}"
        end
        status
      end

      def parse_header_section(message)
        message.state = :headers
        header_seen = false
        loop do
          source = message.source
          break if source.eof?
          type = source.readbyte
          case type
          when KNOWN_FIELDS
            raise ParseError, "multiple header field sections are not permitted" if header_seen
            read_known_fields(source, message.headers)
            header_seen = true
          when INDETERMINATE_FIELDS
            raise ParseError, "multiple header field sections are not permitted" if header_seen
            read_indeterminate_fields(source, message.headers)
            header_seen = true
          when KNOWN_CONTENT, INDETERMINATE_CONTENT,
               KNOWN_TRAILERS, INDETERMINATE_TRAILERS
            source.ungetbyte(type)
            message.state = :body_frames
            return
          when KNOWN_PADDING
            length = source.varint
            padding = source.read_exact(length)
            raise ParseError, "padding must contain zero bytes" unless padding.delete("\0".b).empty?
          when INDETERMINATE_PADDING
            source.ungetbyte(type)
            message.state = :padding
            return
          else
            raise ParseError, "invalid header frame type #{type}"
          end
        end
        message.state = :complete
      end

      def add_informational(message, nested)
        message.informational.concat(nested.informational)
        message.informational << {status: nested.status, headers: nested.headers_hash}
        message.headers.clear
      end

      def parse_body_frame(message, type)
        source = message.source
        case type
        when KNOWN_CONTENT
          length = source.varint
          message.body_reader = BoundedReader.new(source, length, max_length: @max_length)
          message.state = :body_open
        when INDETERMINATE_CONTENT
          message.body_reader = ChunkedReader.new(source)
          message.state = :body_open
        when KNOWN_TRAILERS
          raise ParseError, "multiple trailer sections are not permitted" if message.trailers.any?
          read_known_fields(source, message.trailers)
          finish_message(message)
        when INDETERMINATE_TRAILERS
          raise ParseError, "multiple trailer sections are not permitted" if message.trailers.any?
          read_indeterminate_fields(source, message.trailers)
          finish_message(message)
        when KNOWN_PADDING
          length = source.varint
          padding = source.read_exact(length)
          raise ParseError, "padding must contain zero bytes" unless padding.delete("\0".b).empty?
          message.state = :body_frames
        when INDETERMINATE_PADDING
          message.state = :padding
        else
          raise ParseError, "invalid body frame type #{type}"
        end
      end

      def skip_padding(message)
        source = message.source
        loop do
          return finish_message(message) if source.eof?
          byte = source.readbyte
          if byte == INDETERMINATE_PADDING
            skip_zero_padding(source)
            finish_message(message)
            return
          else
            source.ungetbyte(byte)
            message.state = :body_frames
            return
          end
        end
      end

      def skip_zero_padding(source)
        until source.eof?
          byte = source.readbyte
          raise ParseError, "padding must contain zero bytes" unless byte.zero?
        end
      end

      def read_known_fields(source, fields)
        length = source.varint
        section = if source.equal?(@reader)
          bounded(length)
        else
          BoundedReader.new(source, length, max_length: @max_length)
        end
        read_field_lines(section, fields, true)
        section.finish!
      end

      def read_indeterminate_fields(source, fields)
        read_field_lines(source, fields, true)
      end

      def read_field_lines(source, fields, bounded)
        loop do
          break if source.eof?
          type = source.readbyte
          case type
          when 0
            terminator = source.eof?
            unless terminator
              byte = source.readbyte
              if byte.zero? && source.eof?
                break
              end
              source.ungetbyte(byte)
            end
            if terminator
              break
            end
            name_length = Varint.read(source, max_length: nil)
            raise ParseError, "field name cannot be empty" if name_length.zero?
            name = source.read_exact(name_length)
            value_length = Varint.read(source, max_length: nil)
            value = source.read_exact(value_length)
            add_field(fields, name, value)
          when 1
            unless bounded
              raise ParseError, "indeterminate field line must terminate a field section"
            end
            name_length = Varint.read(source, max_length: nil)
            raise ParseError, "field name cannot be empty" if name_length.zero?
            name = source.read_exact(name_length)
            value = source.read
            add_field(fields, name, value.to_s)
            break
          else
            raise ParseError, "invalid field line type #{type}"
          end
        end
      end

      def add_field(fields, name, value)
        name = BinaryHTTP.binary(name)
        value = BinaryHTTP.binary(value)
        unless name.match?(/\A[!-#$%&'*+\-.^_`|~0-9A-Za-z]+\z/n)
          raise ParseError, "invalid field name"
        end
        if value.match?(/[\0\r\n]/n)
          raise ParseError, "invalid field value"
        end
        fields << FieldLine.new(name, value)
      end

    end

    class << self
      def decode_request(io, max_length: DEFAULT_MAX_LENGTH)
        MessageParser.new(io, max_length: max_length).parse_request
      end

      def decode_response(io, max_length: DEFAULT_MAX_LENGTH)
        MessageParser.new(io, max_length: max_length).parse_response
      end
    end

    class Encoder
      def initialize(output = String.new(encoding: BINARY))
        @output = output
      end

      def to_str
        @output
      end

      def request(method:, path:, scheme: "http", authority: "", headers: nil, body: nil,
                  trailers: nil, framing: :known, field_framing: nil,
                  content_framing: nil, trailer_framing: nil, informational: nil)
        headers = normalize_fields(headers)
        raise ArgumentError, "requests cannot contain informational responses" if informational
        payload = String.new(encoding: BINARY)
        write_request_control(payload, method, scheme, authority, path)
        write_fields(payload, headers, field_framing == :indeterminate ? INDETERMINATE_FIELDS : KNOWN_FIELDS)
        write_content(payload, body, trailers, content_framing || :known, trailer_framing)
        wrap(@output, payload, framing == :known ? KNOWN_REQUEST : INDETERMINATE_REQUEST, framing == :known)
      end

      def response(status:, headers: nil, body: nil, trailers: nil, framing: :known,
                   field_framing: nil, content_framing: nil, trailer_framing: nil,
                   informational: nil)
        payload = String.new(encoding: BINARY)
        Array(informational).each do |item|
          write_interim(payload, item, framing)
        end
        Varint.encode(Integer(status), payload)
        write_fields(payload, normalize_fields(headers),
          field_framing == :indeterminate ? INDETERMINATE_FIELDS : KNOWN_FIELDS)
        write_content(payload, body, trailers, content_framing || :known, trailer_framing)
        final_type = framing == :known ? KNOWN_FINAL_RESPONSE : INDETERMINATE_FINAL_RESPONSE
        wrap(@output, payload, final_type, framing == :known)
      end

      def rack_request(env, framing: :known, content_framing: nil)
        RackAdapter.encode_request(env, self, framing: framing, content_framing: content_framing)
      end

      def rack_response(tuple, framing: :known, content_framing: nil)
        RackAdapter.encode_response(tuple, self, framing: framing, content_framing: content_framing)
      end

      private

      def write_interim(output, item, framing)
        status = item.fetch(:status)
        payload = String.new(encoding: BINARY)
        Varint.encode(Integer(status), payload)
        write_fields(payload, normalize_fields(item[:headers]), KNOWN_FIELDS)
        wrap(output, payload, KNOWN_INTERIM_RESPONSE, true)
      end

      def wrap(output, payload, type, known)
        output << type.chr(BINARY)
        Varint.encode(payload.bytesize, output) if known
        output << payload
        output
      end

      def write_request_control(output, method, scheme, authority, path)
        control = String.new(encoding: BINARY)
        [method, scheme, authority, path].each do |value|
          value = BinaryHTTP.binary(value)
          Varint.encode(value.bytesize, control)
          control << value
        end
        Varint.encode(control.bytesize, output)
        output << control
      end

      def normalize_fields(headers)
        return [] if headers.nil?
        fields = []
        headers.each do |entry|
          name, value = entry.is_a?(Array) && entry.length == 2 ? entry : [entry, nil]
          Array(value).each { |item| fields << [BinaryHTTP.binary(name), BinaryHTTP.binary(item)] }
        end
        fields
      end

      def write_fields(output, fields, type)
        if [KNOWN_FIELDS, KNOWN_TRAILERS].include?(type)
          payload = field_payload(fields)
          output << type.chr(BINARY)
          Varint.encode(payload.bytesize, output)
          output << payload
        else
          output << type.chr(BINARY)
          output << field_payload(fields)
          output << 0.chr(BINARY)
        end
      end

      def field_payload(fields)
        payload = String.new(encoding: BINARY)
        fields.each do |name, value|
          payload << 0.chr(BINARY)
          Varint.encode(name.bytesize, payload)
          payload << name
          Varint.encode(value.bytesize, payload)
          payload << value
        end
        payload
      end

      def write_content(output, body, trailers, mode, trailer_mode = nil)
        trailer_fields = normalize_fields(trailers)
        if body.nil? || empty_body?(body)
          if trailer_fields.any?
            write_fields(output, trailer_fields,
              trailer_mode == :indeterminate ? INDETERMINATE_TRAILERS : KNOWN_TRAILERS)
          end
          return
        end

        if mode == :known
          data = read_body(body)
          output << KNOWN_CONTENT.chr(BINARY)
          Varint.encode(data.bytesize, output)
          output << data
          if trailer_fields.any?
            write_fields(output, trailer_fields,
              trailer_mode == :indeterminate ? INDETERMINATE_TRAILERS : KNOWN_TRAILERS)
          end
        else
          output << INDETERMINATE_CONTENT.chr(BINARY)
          each_body(body) do |chunk|
            chunk = BinaryHTTP.binary(chunk)
            Varint.encode(chunk.bytesize, output)
            output << chunk
          end
          Varint.encode(0, output)
          if trailer_fields.any?
            write_fields(output, trailer_fields,
              trailer_mode == :indeterminate ? INDETERMINATE_TRAILERS : KNOWN_TRAILERS)
          end
        end
      end

      def empty_body?(body)
        body.respond_to?(:empty?) && body.empty?
      end

      def read_body(body)
        if body.respond_to?(:read)
          result = String.new(encoding: BINARY)
          while (chunk = body.read(16 * 1024))
            result << chunk.b
          end
          result
        elsif body.respond_to?(:each)
          result = String.new(encoding: BINARY)
          body.each { |chunk| result << chunk.b }
          result
        else
          BinaryHTTP.binary(body)
        end
      end

      def each_body(body)
        if body.respond_to?(:each)
          body.each { |chunk| yield chunk }
        elsif body.respond_to?(:read)
          while (chunk = body.read(16 * 1024))
            yield chunk
          end
        else
          yield body
        end
      end
    end

    module RackAdapter
      module_function

      class RequestTrailers
        def initialize(message)
          @message = message
        end

        def to_h
          @message.read_trailers
          @message.trailers_hash
        end

        def [](name)
          to_h[name]
        end
      end

      def request_env(message, input: true, trailers: nil)
        request_path, query = split_path(message.path)
        authority = message.authority.to_s
        host, port = split_authority(authority)
        env = {
          "REQUEST_METHOD" => message.method.dup.b,
          "SCRIPT_NAME" => String.new(encoding: BINARY),
          "PATH_INFO" => request_path.b,
          "QUERY_STRING" => query.b,
          "SERVER_NAME" => host.b,
          "SERVER_PORT" => port.to_s.b,
          "SERVER_PROTOCOL" => "HTTP/1.1".b,
          "rack.url_scheme" => message.scheme.dup.b,
          "HTTPS" => (message.scheme == "https" ? "on" : "off").b,
          "rack.errors" => StringIO.new,
          "rack.version" => [1, 3],
        }
        env["HTTP_HOST"] = authority.b unless authority.empty?
        apply_request_headers(env, message.headers)
        if trailers
          env[trailers] = RequestTrailers.new(message)
        end
        if input
          env["rack.input"] = BodyInput.new(message)
        end
        env
      end

      def response_tuple(message, on_informational: nil)
        message.informational.each do |item|
          on_informational&.call(item[:status], item[:headers])
        end
        headers = message.headers_hash
        body = ResponseBody.new(message)
        [message.status, headers, body]
      end

      def encode_request(env, encoder, framing:, content_framing:)
        headers = env_headers(env)
        body = env["rack.input"]
        authority = env["HTTP_HOST"] || [env["SERVER_NAME"], default_port?(env) ? nil : env["SERVER_PORT"]].compact.join(":")
        path = [env["PATH_INFO"], query_part(env["QUERY_STRING"])].join
        encoder.request(
          method: env.fetch("REQUEST_METHOD"),
          scheme: env["rack.url_scheme"] || (env["HTTPS"] == "on" ? "https" : "http"),
          authority: authority,
          path: path,
          headers: headers,
          body: body,
          framing: framing,
          content_framing: content_framing
        )
      end

      def encode_response(tuple, encoder, framing:, content_framing:)
        status, headers, body = tuple
        encoder.response(
          status: status,
          headers: headers,
          body: body,
          framing: framing,
          content_framing: content_framing
        )
      end

      def split_path(path)
        target, query = path.to_s.split("?", 2)
        target = "/" if target.to_s.empty?
        [target, query.to_s]
      end

      def split_authority(authority)
        host, port = authority.sub(/\A\[/, "").sub(/\]\z/, "").rpartition(":").values_at(0, 2)
        if port && port.match?(/\A\d+\z/)
          [host, port]
        else
          [authority, "80"]
        end
      end

      def default_port?(env)
        (env["rack.url_scheme"] == "https" && env["SERVER_PORT"] == "443") ||
          (env["rack.url_scheme"] != "https" && env["SERVER_PORT"] == "80")
      end

      def query_part(query)
        query.to_s.empty? ? "" : "?#{query}"
      end

      def apply_request_headers(env, fields)
        fields.each do |field|
          key = "HTTP_#{field.name.upcase.tr('-', '_')}"
          case key
          when "HTTP_CONTENT_TYPE"
            key = "CONTENT_TYPE"
          when "HTTP_CONTENT_LENGTH"
            key = "CONTENT_LENGTH"
          when "HTTP_HOST"
            next
          end
          add_header(env, key, field.value)
        end
      end

      def env_headers(env)
        env.filter_map do |key, value|
          next if key.start_with?("rack.") || !key.is_a?(String)
          name = case key
          when "CONTENT_TYPE" then "content-type"
          when "CONTENT_LENGTH" then "content-length"
          when /\AHTTP_/
            key[5..].downcase.tr("_", "-")
          end
          next unless name
          next if name == "host"
          [name, value]
        end
      end

      def add_header(env, key, value)
        if env.key?(key)
          env[key] = [env[key], value].flatten.join("\n")
        else
          env[key] = value
        end
      end

      class ResponseBody
        def initialize(message)
          @message = message
        end

        def each
          return enum_for(:each) unless block_given?
          @message.each_body { |chunk| yield chunk }
        end

        def trailers
          @message.read_trailers
          @message.trailers_hash
        end
      end
    end

    def self.encode_request(**options)
      Encoder.new.request(**options)
    end

    def self.encode_response(**options)
      Encoder.new.response(**options)
    end
  end
end
