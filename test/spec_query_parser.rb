# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/query_parser'
end

describe Rack::QueryParser do
  it "can normalize values with missing values" do
    query_parser = Rack::QueryParser.make_default(8)
    query_parser.parse_nested_query("a=a").must_equal({"a" => "a"})
    query_parser.parse_nested_query("a=").must_equal({"a" => ""})
    query_parser.parse_nested_query("a").must_equal({"a" => nil})
    query_parser.parse_query_pairs("a=a").must_equal([["a", "a"]])
    query_parser.parse_query_pairs("a=").must_equal([["a", ""]])
    query_parser.parse_query_pairs("a").must_equal([["a", nil]])
  end

  it "accepts bytesize_limit to specify maximum size of query string to parse" do
    query_parser = Rack::QueryParser.make_default(32, bytesize_limit: 3)
    query_parser.parse_query("a=a").must_equal({"a" => "a"})
    query_parser.parse_nested_query("a=a").must_equal({"a" => "a"})
    query_parser.parse_nested_query("a=a", '&').must_equal({"a" => "a"})
    query_parser.parse_query_pairs("a=a").must_equal([["a", "a"]])
    proc { query_parser.parse_query("a=aa") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_nested_query("a=aa") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_nested_query("a=aa", '&') }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_query_pairs("a=aa") }.must_raise Rack::QueryParser::QueryLimitError
  end

  it "does not enforce a bytesize limit when bytesize_limit is nil" do
    query_parser = Rack::QueryParser.make_default(32, bytesize_limit: nil)
    query_parser.parse_query("a=aa").must_equal({"a" => "aa"})
    query_parser.parse_nested_query("a=aa").must_equal({"a" => "aa"})
    query_parser.parse_nested_query("a=aa", '&').must_equal({"a" => "aa"})
    query_parser.parse_query_pairs("a=aa").must_equal([["a", "aa"]])
  end

  it "accepts params_limit to specify maximum number of query parameters to parse" do
    query_parser = Rack::QueryParser.make_default(32, params_limit: 2)
    query_parser.parse_query("a=a&b=b").must_equal({"a" => "a", "b" => "b"})
    query_parser.parse_nested_query("a=a&b=b").must_equal({"a" => "a", "b" => "b"})
    query_parser.parse_nested_query("a=a&b=b", '&').must_equal({"a" => "a", "b" => "b"})
    query_parser.parse_query_pairs("a=a&b=b").must_equal([["a", "a"], ["b", "b"]])
    query_parser.parse_query_pairs("a=1&a=2").must_equal([["a", "1"], ["a", "2"]])
    proc { query_parser.parse_query("a=a&b=b&c=c") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_nested_query("a=a&b=b&c=c", '&') }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_query("b[]=a&b[]=b&b[]=c") }.must_raise Rack::QueryParser::QueryLimitError
    proc { query_parser.parse_query_pairs("a=a&b=b&c=c") }.must_raise Rack::QueryParser::QueryLimitError
  end

  it "does not enforce a params limit when params_limit is nil" do
    query_parser = Rack::QueryParser.make_default(32, params_limit: nil)
    query_parser.parse_query("a=a&b=b&c=c").must_equal({"a" => "a", "b" => "b", "c" => "c"})
    query_parser.parse_nested_query("a=a&b=b&c=c").must_equal({"a" => "a", "b" => "b", "c" => "c"})
  end

  it "raises when normalizing params with incompatible encoding such as UTF-16LE" do
    query_parser = Rack::QueryParser.make_default(8)
    name = "utf-16le".dup.force_encoding("UTF-16LE")
    value = "Alice?".dup.force_encoding("UTF-16LE")
    lambda {
      query_parser.normalize_params({}, name, value)
    }.must_raise(::Rack::QueryParser::IncompatibleEncodingError)
  end

  it "parses nested query in strict mode, recording the origin of every leaf value" do
    query_parser = Rack::QueryParser.make_default(8)
    result = query_parser.parse_nested_query_strict("a[b]=1&c[]=x&c[]=y", source: "query string")
    result.params.must_equal({"a" => {"b" => "1"}, "c" => ["x", "y"]})
    result.to_h.must_equal({"a" => {"b" => "1"}, "c" => ["x", "y"]})
    result["a"].must_equal({"b" => "1"})
    result.source.must_equal "query string"
    result.leaves.map { |leaf| [leaf.path, leaf.key, leaf.raw_key, leaf.value, leaf.range, leaf.source] }.must_equal([
      [["a", "b"], "a[b]", "a[b]", "1", 0...6, "query string"],
      [["c", 0], "c[]", "c[]", "x", 7...12, "query string"],
      [["c", 1], "c[]", "c[]", "y", 13...18, "query string"],
    ])
  end

  it "handles empty input in strict mode" do
    query_parser = Rack::QueryParser.make_default(8)
    query_parser.parse_nested_query_strict(nil).params.must_equal({})
    query_parser.parse_nested_query_strict("").params.must_equal({})
    query_parser.parse_nested_query_strict("").leaves.must_equal([])
  end

  it "rejects duplicate scalar assignments in strict mode, locating both inputs" do
    query_parser = Rack::QueryParser.make_default(8)
    error = proc {
      query_parser.parse_nested_query_strict("a[b]=1&a%5Bb%5D=2", source: "query string")
    }.must_raise Rack::QueryParser::AmbiguousParameterError
    error.must_be_kind_of Rack::QueryParser::InvalidParameterError
    error.path.must_equal ["a", "b"]
    error.message.must_include "parameter `a[b]'"
    error.message.must_include "`a[b]=1' (query string, bytes 0...6)"
    error.message.must_include "`a%5Bb%5D=2' (query string, bytes 7...17)"

    proc { query_parser.parse_nested_query_strict("a=1&a=2") }.
      must_raise Rack::QueryParser::AmbiguousParameterError
    proc { query_parser.parse_nested_query_strict("a[0][b]=1&a[0][b]=2") }.
      must_raise Rack::QueryParser::AmbiguousParameterError
  end

  it "rejects scalar assignments that replace a structure in strict mode" do
    query_parser = Rack::QueryParser.make_default(8)
    error = proc {
      query_parser.parse_nested_query_strict("a[b][c]=1&a[b]=2")
    }.must_raise Rack::QueryParser::AmbiguousParameterError
    error.path.must_equal ["a", "b"]
    error.message.must_include "`a[b][c]=1' (bytes 0...9)"
    error.message.must_include "`a[b]=2' (bytes 10...16)"

    proc { query_parser.parse_nested_query_strict("a[]=1&a=2") }.
      must_raise Rack::QueryParser::AmbiguousParameterError
  end

  it "allows appending to arrays in strict mode" do
    query_parser = Rack::QueryParser.make_default(8)
    query_parser.parse_nested_query_strict("a[]=1&a[]=2").params.
      must_equal({"a" => ["1", "2"]})
  end

  it "attributes values inside arrays to the element they belong to in strict mode" do
    query_parser = Rack::QueryParser.make_default(8)
    # The second a[][b] starts a new array element, so it is not a conflict
    query_parser.parse_nested_query_strict("a[][b]=1&a[][b]=2").params.
      must_equal({"a" => [{"b" => "1"}, {"b" => "2"}]})
    query_parser.parse_nested_query_strict("a[][b]=1&a[][c]=2&a[][b]=3").params.
      must_equal({"a" => [{"b" => "1", "c" => "2"}, {"b" => "3"}]})
  end

  it "still allows duplicate assignments in non-strict mode" do
    query_parser = Rack::QueryParser.make_default(8)
    query_parser.parse_nested_query("a[b]=1&a[b]=2").must_equal({"a" => {"b" => "2"}})
    query_parser.parse_nested_query("a=1&a=2").must_equal({"a" => "2"})
  end

  it "enforces the depth, bytesize and params limits in strict mode" do
    proc { Rack::QueryParser.make_default(2).parse_nested_query_strict("a[b][c]=1") }.
      must_raise Rack::QueryParser::QueryLimitError
    proc { Rack::QueryParser.make_default(32, bytesize_limit: 3).parse_nested_query_strict("a=aa") }.
      must_raise Rack::QueryParser::QueryLimitError
    proc { Rack::QueryParser.make_default(32, params_limit: 2).parse_nested_query_strict("a=1&b=2&c=3") }.
      must_raise Rack::QueryParser::QueryLimitError
  end

  it "merges strict results from different sources, reporting the source of conflicts" do
    query_parser = Rack::QueryParser.make_default(8)
    query = query_parser.parse_nested_query_strict("a[b]=1&c[]=1", source: "query string")
    form = query_parser.parse_nested_query_strict("a[d]=2&c[]=2", source: "form body")

    merged = query.merge(form)
    merged.params.must_equal({"a" => {"b" => "1", "d" => "2"}, "c" => ["1", "2"]})
    merged.leaves.map(&:source).must_equal ["query string", "query string", "form body", "form body"]

    query = query_parser.parse_nested_query_strict("a[b]=1", source: "query string")
    form = query_parser.parse_nested_query_strict("a%5Bb%5D=2", source: "form body")
    error = proc { query.merge(form) }.must_raise Rack::QueryParser::AmbiguousParameterError
    error.path.must_equal ["a", "b"]
    error.message.must_include "`a[b]=1' (query string, bytes 0...6)"
    error.message.must_include "`a%5Bb%5D=2' (form body, bytes 0...10)"

    query = query_parser.parse_nested_query_strict("a[b][c]=1", source: "query string")
    form = query_parser.parse_nested_query_strict("a[b]=2", source: "form body")
    proc { query.merge(form) }.must_raise Rack::QueryParser::AmbiguousParameterError
  end
end
