# frozen_string_literal: true

require_relative 'helper'
require_relative '../lib/rack/binary_http'
require_relative '../lib/rack/lint'

describe Rack::BinaryHTTP do
  ChunkIO = Struct.new(:data, :chunk_size, :offset) do
    def initialize(data, chunk_size)
      super(data.b, chunk_size, 0)
    end

    def read(length = nil)
      return nil if offset >= data.bytesize
      amount = [length || chunk_size, chunk_size, data.bytesize - offset].min
      chunk = data.byteslice(offset, amount)
      self.offset += amount
      chunk
    end

    def getbyte
      read(1)&.getbyte(0)
    end

    def eof?
      offset >= data.bytesize
    end
  end

  def decode_at_every_split(bytes, kind:)
    bhttp = Rack::BinaryHTTP
    (0..bytes.bytesize).map do |index|
      io = StringIO.new(bytes.byteslice(index..) || String.new)
      message = kind == :request ?
      bhttp.decode_request(io) :
        bhttp.decode_response(io)
      yield message
    end
  end

  def assert_every_split(bytes, kind: :request)
    bhttp = Rack::BinaryHTTP
    (1..bytes.bytesize).each do |chunk_size|
      io = ChunkIO.new(bytes, chunk_size)
      message = kind == :request ?
        bhttp.decode_request(io) :
        bhttp.decode_response(io)
      yield message, chunk_size
    end
  end

  def hex(data)
    data.unpack1("H*")
  end

  def bhttp
    Rack::BinaryHTTP
  end

  it "encodes and decodes a known-length request fixed vector" do
    expected = "002d1e034745540568747470730c6578616d706c652e74657374062f68656c6c6f030c0006782d7465737403796573".b
    bytes = bhttp.encode_request(
      method: "GET",
      scheme: "https",
      authority: "example.test",
      path: "/hello",
      headers: [["x-test", "yes"]],
      framing: :known
    )

    assert_equal expected, hex(bytes).b

    request = bhttp.decode_request(StringIO.new(bytes))
    assert_equal ["GET", "https", "example.test", "/hello"],
      [request.method, request.scheme, request.authority, request.path]
    assert_equal "yes", request.headers_hash["x-test"]
    assert_equal "", request.read
  end

  it "encodes and decodes both outer framing modes with trailers" do
    variants = [
      {framing: :known, content_framing: :known, trailer_framing: :known},
      {framing: :known, content_framing: :indeterminate, trailer_framing: :known},
      {framing: :indeterminate, content_framing: :known, trailer_framing: :known},
      {framing: :indeterminate, content_framing: :indeterminate, trailer_framing: :known},
    ]

    variants.each do |options|
      bytes = bhttp.encode_request(
        method: "POST",
        scheme: "http",
        authority: "x.test",
        path: "/a?b=c",
        headers: [["content-type", "text/plain"], ["x-many", "1"], ["x-many", "2"]],
        body: "abcdef",
        trailers: [["x-trailer", "done"]],
        **options
      )

      request = bhttp.decode_request(StringIO.new(bytes))
      assert_equal "POST", request.method
      assert_equal "/a?b=c", request.path
      assert_equal ["1", "2"], request.headers_hash["x-many"]
      assert_equal "abcdef", request.read
      assert_equal "done", request.trailers_hash["x-trailer"]
    end
  end

  it "parses indeterminate field sections that end at frame boundary" do
    bytes = bhttp.encode_request(
      method: "GET", scheme: "http", authority: "", path: "/",
      headers: [["x-a", "1"]], field_framing: :indeterminate
    )
    request = bhttp.decode_request(StringIO.new(bytes))
    assert_equal "1", request.headers_hash["x-a"]
  end

  it "streams request bodies without buffering the complete body" do
    chunks = Enumerator.new do |yielder|
      100.times { yielder << "x" * 997 }
    end
    body = Object.new
    body.define_singleton_method(:each) do |&block|
      chunks.each(&block)
    end

    bytes = bhttp.encode_request(
      method: "PUT", scheme: "http", authority: "x", path: "/",
      headers: [], body: body, framing: :indeterminate, content_framing: :indeterminate
    )

    request = bhttp.decode_request(StringIO.new(bytes))
    seen = 0
    request.each_body { |chunk| seen += chunk.bytesize }
    assert_equal 99_700, seen
  end

  it "keeps indeterminate request bodies lazy while decoding headers" do
    requested = 0
    body = Object.new
    body.define_singleton_method(:each) do |&block|
      10.times do
        requested += 1
        block.call("chunk\n")
      end
    end
    bytes = bhttp.encode_request(method: "POST", scheme: "http", authority: "x",
      path: "/", headers: [], body: body, framing: :indeterminate,
      content_framing: :indeterminate)
    request = bhttp.decode_request(StringIO.new(bytes))
    assert_equal "POST", request.method
    chunks = []
    request.each_body { |chunk| chunks << chunk }
    assert_equal 10, chunks.length
  end

  it "decodes requests at every single-byte split point" do
    bytes = bhttp.encode_request(
      method: "POST", scheme: "https", authority: "a.test", path: "/x?y",
      headers: [["x-a", "1"], ["x-b", "2"]],
      body: "binary\0body".b,
      trailers: [["x-done", "ok"]],
      framing: :known
    )

    assert_every_split(bytes) do |request, _index|
      assert_equal "POST", request.method
      assert_equal "binary\0body".b, request.read
      assert_equal "ok", request.trailers_hash["x-done"]
    end
  end

  it "decodes indeterminate requests at every single-byte split point" do
    bytes = bhttp.encode_request(
      method: "POST", scheme: "https", authority: "a.test", path: "/x",
      headers: [["x-a", "1"]], body: "abc",
      framing: :indeterminate, content_framing: :indeterminate
    )

    assert_every_split(bytes) do |request, _index|
      assert_equal "abc", request.read
    end
  end

  it "supports informational responses" do
    bytes = bhttp.encode_response(
      status: 200,
      headers: [["x-final", "yes"]],
      body: "body",
      informational: [{status: 103, headers: [["link", "</style>; rel=preload"]]}],
      framing: :known
    )
    response = bhttp.decode_response(StringIO.new(bytes))
    assert_equal 103, response.informational.dig(0, :status)
    assert_equal "</style>; rel=preload", response.informational.dig(0, :headers, "link")
    assert_equal 200, response.status
    assert_equal "yes", response.headers_hash["x-final"]
    assert_equal "body", response.read
  end

  it "decodes responses and indeterminate inner frames at every delivery chunk size" do
    variants = [
      {framing: :known, content_framing: :known},
      {framing: :indeterminate, content_framing: :indeterminate},
      {framing: :known, field_framing: :indeterminate},
    ]
    variants.each do |options|
      bytes = bhttp.encode_response(
        status: 201,
        headers: [["x-a", "1"]],
        body: nil,
        trailers: nil,
        informational: options[:framing] == :known ?
          [{status: 103, headers: [["link", "ready"]]}] : nil,
        **options
      )
      assert_every_split(bytes, kind: :response) do |response, _chunk|
        if options[:framing] == :known
          assert_equal 103, response.informational.dig(0, :status)
        end
        assert_equal 201, response.status
        assert_equal "1", response.headers_hash["x-a"]
        assert_equal "", response.read
      end
    end
  end

  it "parses indeterminate padding until message end" do
    bytes = bhttp.encode_request(method: "GET", scheme: "http", authority: "x",
      path: "/", headers: [], framing: :known)
    bytes << "\x0d\x00\x00".b
    bytes.setbyte(1, bytes.bytesize - 2)
    request = bhttp.decode_request(StringIO.new(bytes))
    assert_equal "", request.read

    bad = bytes.dup
    bad.setbyte(bad.bytesize - 1, 1)
    bad.setbyte(1, bad.bytesize - 2)
    bad_request = bhttp.decode_request(StringIO.new(bad))
    assert_raises(bhttp::ParseError) do
      bad_request.read
    end
  end

  it "adapts a decoded request to a Rack env and back to Binary HTTP" do
    bytes = bhttp.encode_request(
      method: "PUT", scheme: "https", authority: "example.test:8443",
      path: "/items?a=b", headers: [["content-type", "text/plain"]],
      body: "payload", trailers: [["x-done", "yes"]],
      framing: :indeterminate, content_framing: :indeterminate
    )

    app = lambda do |env|
      body = env["rack.input"].read
      [200, {
        "x-method" => env["REQUEST_METHOD"],
        "x-path" => env["PATH_INFO"],
        "x-query" => env["QUERY_STRING"],
        "x-host" => env["HTTP_HOST"],
        "x-content-type" => env["CONTENT_TYPE"],
        "x-body" => body,
        "x-trailer" => env["rack.trailers"].to_h["x-done"],
      }, []]
    end

    request = bhttp.decode_request(StringIO.new(bytes))
    env = request.to_rack_env(trailers: "rack.trailers")
    status, headers, lint_body = Rack::Lint.new(app).call(env)
    assert_equal 200, status
    assert_equal "PUT", headers["x-method"]
    assert_equal "/items", headers["x-path"]
    assert_equal "a=b", headers["x-query"]
    assert_equal "example.test:8443", headers["x-host"]
    assert_equal "text/plain", headers["x-content-type"]
    assert_equal "payload", headers["x-body"]
    assert_equal "yes", headers["x-trailer"]
    assert_equal [], lint_body.each.to_a
  end

  it "encodes a Rack environment back to Binary HTTP" do
    original = bhttp.encode_request(method: "PATCH", scheme: "https",
      authority: "rack.test", path: "/rack?z=9",
      headers: [["content-type", "application/json"]],
      body: '{"ok":true}', framing: :known)
    request = bhttp.decode_request(StringIO.new(original))
    env = request.to_rack_env
    encoded = Rack::BinaryHTTP::Encoder.new.rack_request(env)
    roundtrip = bhttp.decode_request(StringIO.new(encoded))
    assert_equal "PATCH", roundtrip.method
    assert_equal "https", roundtrip.scheme
    assert_equal "rack.test", roundtrip.authority
    assert_equal "/rack?z=9", roundtrip.path
    assert_equal "application/json", roundtrip.headers_hash["content-type"]
    assert_equal '{"ok":true}', roundtrip.read
  end

  it "encodes a Rack response triple back to Binary HTTP" do
    tuple = [202, {"content-type" => "text/plain"}, ["hello", " ", "rack"]]
    bytes = Rack::BinaryHTTP::Encoder.new.rack_response(tuple, framing: :indeterminate)
    response = bhttp.decode_response(StringIO.new(bytes))
    assert_equal 202, response.status
    assert_equal "text/plain", response.headers_hash["content-type"]
    assert_equal "hello rack", response.read
  end

  it "distinguishes truncation, control-data, length, and syntax errors" do
    valid = bhttp.encode_request(method: "GET", scheme: "http",
      authority: "x", path: "/", headers: [], framing: :known)
    (1...valid.bytesize).each do |index|
      assert_raises(bhttp::TruncatedError) do
      bhttp.decode_request(StringIO.new(valid.byteslice(0, index)))
      end
    end

    assert_raises(bhttp::ControlDataError) do
      invalid_control = ["000805012000000000"].pack("H*")
      bhttp.decode_request(StringIO.new(invalid_control))
    end
    assert_raises(bhttp::LengthError) do
      bhttp.decode_request(StringIO.new(valid), max_length: 1)
    end
    assert_raises(bhttp::ParseError) do
      bhttp.decode_request(StringIO.new("\x06".b))
    end
  end

  it "accepts omitted authority, empty fields, padding, and indeterminate field lines" do
    omitted = ["000d0c03474554046874747000012f"].pack("H*")
    request = bhttp.decode_request(StringIO.new(omitted))
    assert_equal ["GET", "http", "", "/"],
      [request.method, request.scheme, request.authority, request.path]
    assert_equal({}, request.headers_hash)

    padded = bhttp.encode_request(method: "GET", scheme: "http", authority: "",
      path: "/", headers: [["x", "y"]], body: "x", framing: :known)
    padded.insert(22, "\x06\x01\x00".b)
    padded.setbyte(1, padded.bytesize - 2)
    request = bhttp.decode_request(StringIO.new(padded))
    assert_equal "y", request.headers_hash["x"]
    assert_equal "x", request.read

    bad_padding = padded.dup
    bad_padding.setbyte(24, 1)
    bad_padding.setbyte(1, bad_padding.bytesize - 2)
    assert_raises(bhttp::ParseError) do
      bhttp.decode_request(StringIO.new(bad_padding))
    end
  end

  it "parses indeterminate field lines that consume the rest of a field section" do
    bytes = ["00160c03474554046874747000012f030701017872657374"].pack("H*")
    request = bhttp.decode_request(StringIO.new(bytes))
    assert_equal "rest", request.headers_hash["x"]
  end

  it "rejects oversized declarations and invalid field bytes" do
    assert_raises(bhttp::LengthError) do
      bhttp.decode_request(StringIO.new(["008040"].pack("H*")), max_length: 1)
    end

    invalid_header = bhttp.encode_request(method: "GET", scheme: "http",
      authority: "x", path: "/", headers: [["bad name", "v"]], framing: :known)
    assert_raises(bhttp::ParseError) do
      bhttp.decode_request(StringIO.new(invalid_header))
    end
  end
end
