# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/binary_http'
end

describe Rack::BinaryHTTP do
  BinaryHTTP = Rack::BinaryHTTP

  # An IO that returns at most +chunk+ bytes per read, simulating a
  # source that dribbles out data a few bytes at a time.
  class DripIO
    attr_reader :pos

    def initialize(data, chunk)
      @data = data
      @chunk = chunk
      @pos = 0
    end

    def readpartial(maxlen, out = nil)
      raise EOFError if @pos >= @data.bytesize
      count = [@chunk, maxlen, @data.bytesize - @pos].min
      piece = @data.byteslice(@pos, count)
      @pos += count
      out ? out.replace(piece) : piece
    end
  end

  # GET https://example.com/ with no headers, content, or trailers.
  REQUEST_KNOWN = [
    "00",                   # known-length request
    "03", "474554",         # method "GET"
    "05", "6874747073",     # scheme "https"
    "0b", "6578616d706c652e636f6d", # authority "example.com"
    "01", "2f",             # path "/"
    "00",                   # header section (empty)
    "00",                   # content (empty)
    "00",                   # trailer section (empty)
  ].join

  # 200 OK with a content-type header and "Hello, world!" content.
  RESPONSE_KNOWN = [
    "02",                   # known-length response
    "40c8",                 # status 200
    "18",                   # header section, 24 bytes
    "0c", "636f6e74656e742d74797065", # "content-type"
    "0a", "746578742f706c61696e",     # "text/plain"
    "0d", "48656c6c6f2c20776f726c6421", # content "Hello, world!"
    "00",                   # trailer section (empty)
  ].join

  # POST /upload?x=1 with chunked content "hello" and a trailer.
  REQUEST_INDETERMINATE = [
    "01",                   # indeterminate-length request
    "04", "504f5354",       # method "POST"
    "05", "6874747073",     # scheme "https"
    "0b", "6578616d706c652e636f6d", # authority "example.com"
    "0b", "2f75706c6f61643f783d31",   # path "/upload?x=1"
    "0c", "636f6e74656e742d74797065", # header "content-type"
    "18", "6170706c69636174696f6e2f6f637465742d73747265616d",
    "00",                   # end of header section
    "02", "6865",           # content chunk "he"
    "02", "6c6c",           # content chunk "ll"
    "01", "6f",             # content chunk "o"
    "00",                   # end of content
    "0a", "782d636865636b73756d",     # trailer "x-checksum"
    "03", "616263",         # "abc"
    "00",                   # end of trailer section
  ].join

  # 103 informational response followed by a 200 response with content.
  RESPONSE_INDETERMINATE = [
    "03",                   # indeterminate-length response
    "4067",                 # status 103 (informational)
    "04", "6c696e6b",       # header "link"
    "15", "3c2f612e6373733e3b2072656c3d7072656c6f6164",
    "00",                   # end of informational header section
    "40c8",                 # status 200 (final)
    "00",                   # header section (empty)
    "02", "6f6b",           # content chunk "ok"
    "00",                   # end of content
    "00",                   # end of trailer section
  ].join

  EXPECTED = {
    REQUEST_KNOWN => {
      method: "GET", scheme: "https", authority: "example.com",
      path: "/", headers: [], body: "", trailers: [],
    },
    RESPONSE_KNOWN => {
      status: 200, informational: [],
      headers: [["content-type", "text/plain"]],
      body: "Hello, world!", trailers: [],
    },
    REQUEST_INDETERMINATE => {
      method: "POST", scheme: "https", authority: "example.com",
      path: "/upload?x=1",
      headers: [["content-type", "application/octet-stream"]],
      body: "hello", trailers: [["x-checksum", "abc"]],
    },
    RESPONSE_INDETERMINATE => {
      status: 200,
      informational: [[103, [["link", "</a.css>; rel=preload"]]]],
      headers: [], body: "ok", trailers: [],
    },
  }.freeze

  def bin(vector)
    [vector].pack("H*")
  end

  # Decode every message in +io+, fully consuming each body before
  # moving on, and return [message, body, trailers] triples.
  def decode_all(io, limits: {})
    BinaryHTTP::Decoder.new(io, limits: limits).map do |message|
      body = message.body.read
      [message, body, message.trailers]
    end
  end

  def assert_vector(vector, message, body, trailers)
    expected = EXPECTED.fetch(vector)
    if message.request?
      message.method.must_equal expected[:method]
      message.scheme.must_equal expected[:scheme]
      message.authority.must_equal expected[:authority]
      message.path.must_equal expected[:path]
    else
      message.status.must_equal expected[:status]
      message.informational.must_equal expected[:informational]
    end
    message.headers.must_equal expected[:headers]
    body.must_equal expected[:body]
    trailers.must_equal expected[:trailers]
  end

  it "decodes a known-length request" do
    message, body, trailers = decode_all(StringIO.new(bin(REQUEST_KNOWN))).first
    assert_vector(REQUEST_KNOWN, message, body, trailers)
  end

  it "decodes a known-length response" do
    message, body, trailers = decode_all(StringIO.new(bin(RESPONSE_KNOWN))).first
    assert_vector(RESPONSE_KNOWN, message, body, trailers)
  end

  it "decodes an indeterminate-length request with chunked content and trailers" do
    message, body, trailers = decode_all(StringIO.new(bin(REQUEST_INDETERMINATE))).first
    assert_vector(REQUEST_INDETERMINATE, message, body, trailers)
  end

  it "decodes informational responses" do
    message, body, trailers = decode_all(StringIO.new(bin(RESPONSE_INDETERMINATE))).first
    assert_vector(RESPONSE_INDETERMINATE, message, body, trailers)
  end

  it "decodes every vector at every byte split point" do
    EXPECTED.each_key do |vector|
      data = bin(vector)
      1.upto(data.bytesize) do |chunk|
        triples = decode_all(DripIO.new(data, chunk))
        triples.size.must_equal 1, "split size #{chunk}"
        assert_vector(vector, *triples.first)
      end
    end
  end

  it "decodes a stream of concatenated messages" do
    data = bin(REQUEST_KNOWN) + bin(RESPONSE_KNOWN)
    triples = decode_all(StringIO.new(data))
    triples.size.must_equal 2
    assert_vector(REQUEST_KNOWN, *triples[0])
    assert_vector(RESPONSE_KNOWN, *triples[1])
  end

  it "does not read the content before it is consumed" do
    data = bin(RESPONSE_KNOWN)
    io = DripIO.new(data, 4)
    message = BinaryHTTP.decode_response(io)
    assert io.pos < data.bytesize, "content was read eagerly"
    message.body.read.must_equal "Hello, world!"
  end

  it "round-trips varint boundary values" do
    [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, (1 << 62) - 1].each do |value|
      encoded = BinaryHTTP.encode_varint(value)
      decoded, pos = BinaryHTTP.decode_varint(encoded, 0)
      decoded.must_equal value
      pos.must_equal encoded.bytesize
    end
    assert_raises(ArgumentError) { BinaryHTTP.encode_varint(1 << 62) }
    assert_raises(ArgumentError) { BinaryHTTP.encode_varint(-1) }
  end

  it "encodes requests matching the wire format" do
    encoded = BinaryHTTP.encode_request(
      method: "GET", scheme: "https", authority: "example.com", path: "/")
    encoded.must_equal bin(REQUEST_KNOWN)
  end

  it "encodes responses matching the wire format" do
    encoded = BinaryHTTP.encode_response(
      status: 200, headers: { "content-type" => "text/plain" },
      body: "Hello, world!")
    encoded.must_equal bin(RESPONSE_KNOWN)
  end

  it "encodes indeterminate requests matching the wire format" do
    encoded = BinaryHTTP.encode_request(
      method: "POST", scheme: "https", authority: "example.com",
      path: "/upload?x=1",
      headers: [["content-type", "application/octet-stream"]],
      body: "hello", trailers: [["x-checksum", "abc"]],
      indeterminate: true, chunk_size: 2)
    encoded.must_equal bin(REQUEST_INDETERMINATE)
  end

  it "encodes informational responses matching the wire format" do
    encoded = BinaryHTTP.encode_response(
      status: 200,
      informational: [[103, [["link", "</a.css>; rel=preload"]]]],
      body: "ok", indeterminate: true)
    encoded.must_equal bin(RESPONSE_INDETERMINATE)
  end

  it "round-trips requests in both formats" do
    [false, true].each do |indeterminate|
      encoded = BinaryHTTP.encode_request(
        method: "PUT", scheme: "https", authority: "example.com:8443",
        path: "/a%20b?x=1",
        headers: [["x-token", "abc"], ["content-type", "text/plain"]],
        body: "payload", trailers: [["x-checksum", "abc"]],
        indeterminate: indeterminate)
      message = BinaryHTTP.decode_request(StringIO.new(encoded))
      message.method.must_equal "PUT"
      message.authority.must_equal "example.com:8443"
      message.path.must_equal "/a%20b?x=1"
      message.headers.must_equal [["x-token", "abc"], ["content-type", "text/plain"]]
      message.body.read.must_equal "payload"
      message.trailers.must_equal [["x-checksum", "abc"]]
    end
  end

  it "streams encoded Enumerable bodies without buffering" do
    parts = ["a" * 100, "b" * 100]
    body = parts.each
    encoded = BinaryHTTP.encode_request(
      method: "POST", body: body, indeterminate: true, chunk_size: 10)
    encoded.must_be_kind_of Enumerator
    message = BinaryHTTP.decode_request(StringIO.new(encoded.to_a.join))
    message.body.read.must_equal parts.join
  end

  it "rejects Enumerable bodies for known-length encoding" do
    assert_raises(ArgumentError) do
      BinaryHTTP.encode_request(method: "POST", body: ["x"].each)
    end
  end

  it "treats elided content and trailer sections as empty" do
    data = bin(REQUEST_KNOWN)
    data.bytesize.must_equal 28
    # Cutting exactly before the content (26) or trailer (27) section
    # leaves both sections empty; every other cut is a truncation error.
    (0...data.bytesize).each do |cut|
      io = StringIO.new(data.byteslice(0, cut))
      if [26, 27].include?(cut)
        message = BinaryHTTP.decode_request(io)
        message.body.read.must_equal ""
        message.trailers.must_equal []
      else
        assert_raises(BinaryHTTP::TruncatedMessage, "cut at #{cut}") do
          message = BinaryHTTP.decode_request(io)
          message.body.read
          message.trailers
        end
      end
    end
  end

  it "raises TruncatedMessage for content cut short" do
    data = bin(RESPONSE_KNOWN)
    message = BinaryHTTP.decode_response(StringIO.new(data.byteslice(0, 41)))
    assert_raises(BinaryHTTP::TruncatedMessage) { message.body.read }
  end

  it "raises TruncatedMessage for unterminated indeterminate trailers" do
    data = bin(REQUEST_INDETERMINATE)
    message = BinaryHTTP.decode_request(StringIO.new(data.byteslice(0, data.bytesize - 1)))
    assert_raises(BinaryHTTP::TruncatedMessage) { message.body.read }
  end

  it "raises TruncatedMessage for a varint cut short" do
    assert_raises(BinaryHTTP::TruncatedMessage) do
      BinaryHTTP.decode_response(StringIO.new(bin("0240")))
    end
  end

  it "rejects an unknown framing indicator" do
    assert_raises(BinaryHTTP::InvalidMessage) do
      BinaryHTTP.decode_request(StringIO.new("\x04".b))
    end
  end

  it "rejects empty field names" do
    data = bin(
      "00" "03" "474554" "05" "6874747073" "0b" "6578616d706c652e636f6d" +      "01" "2f" "02" "00" "00" "00" "00")
    assert_raises(BinaryHTTP::InvalidMessage) do
      BinaryHTTP.decode_request(StringIO.new(data))
    end
  end

  it "rejects uppercase field names" do
    data = bin(
      "00" "03" "474554" "05" "6874747073" "0b" "6578616d706c652e636f6d" +      "01" "2f" "04" "01" "58" "01" "61" "00" "00")
    assert_raises(BinaryHTTP::InvalidMessage) do
      BinaryHTTP.decode_request(StringIO.new(data))
    end
  end

  it "rejects field values containing control characters" do
    data = bin(
      "00" "03" "474554" "05" "6874747073" "0b" "6578616d706c652e636f6d" +      "01" "2f" "04" "01" "61" "01" "0d" "00" "00")
    assert_raises(BinaryHTTP::InvalidMessage) do
      BinaryHTTP.decode_request(StringIO.new(data))
    end
  end

  it "rejects invalid response statuses" do
    assert_raises(BinaryHTTP::InvalidMessage) do
      BinaryHTTP.decode_response(StringIO.new(bin("02" "63" "00" "00" "00")))
    end
  end

  it "rejects trailing data after a single message" do
    message = BinaryHTTP.decode_request(StringIO.new(bin(REQUEST_KNOWN) + "\x01".b))
    assert_raises(BinaryHTTP::InvalidMessage) { message.trailers }
  end

  it "ignores zero padding after a single message" do
    message = BinaryHTTP.decode_request(StringIO.new(bin(REQUEST_KNOWN) + "\x00\x00".b))
    message.body.read.must_equal ""
    message.trailers.must_equal []
  end

  it "enforces field section size limits" do
    assert_raises(BinaryHTTP::MessageTooLarge) do
      BinaryHTTP.decode_response(StringIO.new(bin(RESPONSE_KNOWN)),
        limits: { field_section_size: 4 })
    end
  end

  it "enforces field count limits" do
    assert_raises(BinaryHTTP::MessageTooLarge) do
      BinaryHTTP.decode_response(StringIO.new(bin(RESPONSE_KNOWN)),
        limits: { fields: 0 })
    end
  end

  it "enforces declared content length limits" do
    assert_raises(BinaryHTTP::MessageTooLarge) do
      BinaryHTTP.decode_response(StringIO.new(bin(RESPONSE_KNOWN)),
        limits: { content_length: 4 })
    end
  end

  it "enforces streamed content length limits" do
    message = BinaryHTTP.decode_request(StringIO.new(bin(REQUEST_INDETERMINATE)),
      limits: { content_length: 4 })
    assert_raises(BinaryHTTP::MessageTooLarge) { message.body.read }
  end

  it "provides a Rack-compatible input stream" do
    encoded = BinaryHTTP.encode_request(
      method: "POST", body: "one\ntwo\n", indeterminate: true)
    input = BinaryHTTP.decode_request(StringIO.new(encoded)).body
    input.gets.must_equal "one\n"
    input.gets.must_equal "two\n"
    input.gets.must_be_nil

    encoded = BinaryHTTP.encode_request(method: "POST", body: "hello")
    input = BinaryHTTP.decode_request(StringIO.new(encoded)).body
    input.read(2).must_equal "he"
    buffer = String.new
    input.read(2, buffer).must_equal "ll"
    buffer.must_equal "ll"
    input.read(2).must_equal "o"
    input.read(2).must_be_nil
    input.read.must_equal ""
  end

  it "hands a decoded request to a Rack application" do
    app = lambda do |env|
      request_body = env["rack.input"].read
      [200, { "content-type" => "text/plain", "x-echo" => env["HTTP_X_TOKEN"] },
        ["#{env['REQUEST_METHOD']} #{env['PATH_INFO']} #{env['QUERY_STRING']} #{request_body}"]]
    end

    encoded = BinaryHTTP.encode_request(
      method: "POST", scheme: "https", authority: "example.com",
      path: "/submit?a=1",
      headers: [["content-type", "text/plain"], ["x-token", "secret"]],
      body: "payload")
    env = BinaryHTTP.rack_env(BinaryHTTP.decode_request(StringIO.new(encoded)))

    env["REQUEST_METHOD"].must_equal "POST"
    env["PATH_INFO"].must_equal "/submit"
    env["QUERY_STRING"].must_equal "a=1"
    env["CONTENT_TYPE"].must_equal "text/plain"
    env["HTTP_X_TOKEN"].must_equal "secret"
    env["SERVER_NAME"].must_equal "example.com"
    env["SERVER_PORT"].must_equal "443"
    env["rack.url_scheme"].must_equal "https"

    status, headers, body = app.call(env)
    status.must_equal 200
    headers["x-echo"].must_equal "secret"
    body.each.to_a.join.must_equal "POST /submit a=1 payload"
  end

  it "unescapes PATH_INFO" do
    encoded = BinaryHTTP.encode_request(method: "GET", path: "/a%20b")
    env = BinaryHTTP.rack_env(BinaryHTTP.decode_request(StringIO.new(encoded)))
    env["PATH_INFO"].must_equal "/a b"
  end

  it "round-trips a Rack response triple" do
    encoded = BinaryHTTP.from_rack_response(
      200, { "content-type" => "text/plain" }, ["Hello", ", ", "world!"],
      indeterminate: true)
    message = BinaryHTTP.decode_response(StringIO.new(encoded.to_a.join))
    status, headers, body = BinaryHTTP.to_rack_response(message)
    status.must_equal 200
    headers.must_equal({ "content-type" => "text/plain" })
    body.each.to_a.join.must_equal "Hello, world!"
  end

  it "encodes a Rack env back to binary HTTP" do
    env = {
      "REQUEST_METHOD" => "POST",
      "SCRIPT_NAME" => "",
      "PATH_INFO" => "/items",
      "QUERY_STRING" => "x=1",
      "SERVER_NAME" => "example.com",
      "SERVER_PORT" => "8443",
      "HTTP_HOST" => "example.com:8443",
      "rack.url_scheme" => "https",
      "rack.input" => StringIO.new("payload"),
      "CONTENT_TYPE" => "text/plain",
      "HTTP_X_TOKEN" => "abc",
    }
    encoded = BinaryHTTP.from_rack_env(env, indeterminate: true)
    message = BinaryHTTP.decode_request(StringIO.new(encoded.to_a.join))
    message.method.must_equal "POST"
    message.authority.must_equal "example.com:8443"
    message.path.must_equal "/items?x=1"
    message.headers.must_include ["x-token", "abc"]
    message.headers.must_include ["content-type", "text/plain"]
    message.body.read.must_equal "payload"
  end
end
