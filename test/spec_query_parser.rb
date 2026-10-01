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

  it "strict mode returns nested params with leaf origins" do
    query_parser = Rack::QueryParser.make_default(32)
    result = query_parser.parse_nested_query_strict("a[b]=1&c[]=2&c[]=3", '&', source: 'query string')
    result.params.must_equal({"a" => {"b" => "1"}, "c" => ["2", "3"]})
    result.to_h.must_equal result.params
    result.leaves.map { |leaf| [leaf.path, leaf.raw_key, leaf.value, leaf.byte_range, leaf.source] }.must_equal [
      [["a", "b"], "a[b]", "1", 0...6, "query string"],
      [["c", "[]"], "c[]", "2", 7...12, "query string"],
      [["c", "[]"], "c[]", "3", 13...18, "query string"],
    ]
  end

  it "strict mode rejects duplicate scalar assignments to the same path" do
    query_parser = Rack::QueryParser.make_default(32)
    error = proc { query_parser.parse_nested_query_strict("a[b]=1&a%5Bb%5D=2", '&', source: 'query string') }.
      must_raise Rack::QueryParser::ParameterConflictError
    error.message.must_include "duplicate assignment for parameter `a[b]'"
    error.message.must_include "`a[b]' at bytes 0...6 in query string"
    error.message.must_include "`a%5Bb%5D' at bytes 7...17 in query string"
    error.must_be_kind_of Rack::BadRequest
  end

  it "strict mode rejects duplicate assignments at the top level" do
    query_parser = Rack::QueryParser.make_default(32)
    error = proc { query_parser.parse_nested_query_strict("a=1&a=2") }.
      must_raise Rack::QueryParser::ParameterConflictError
    error.message.must_include "duplicate assignment for parameter `a'"
  end

  it "strict mode rejects scalar assignments over structured parameters" do
    query_parser = Rack::QueryParser.make_default(32)
    proc { query_parser.parse_nested_query_strict("a[b]=1&a=2") }.
      must_raise Rack::QueryParser::ParameterConflictError
    proc { query_parser.parse_nested_query_strict("a[]=1&a=2") }.
      must_raise Rack::QueryParser::ParameterConflictError
  end

  it "strict mode allows array appends and tracks array element ownership" do
    query_parser = Rack::QueryParser.make_default(32)
    query_parser.parse_nested_query_strict("a[]=1&a[]=2").params.
      must_equal({"a" => ["1", "2"]})
    query_parser.parse_nested_query_strict("a[][b]=1&a[][b]=2").params.
      must_equal({"a" => [{"b" => "1"}, {"b" => "2"}]})
    query_parser.parse_nested_query_strict("a[][b]=1&a[][c]=2").params.
      must_equal({"a" => [{"b" => "1", "c" => "2"}]})
    query_parser.parse_nested_query_strict("a[][b]=1&a[][c]=2&a[][b]=3").params.
      must_equal({"a" => [{"b" => "1", "c" => "2"}, {"b" => "3"}]})
  end

  it "strict mode raises ParameterTypeError for conflicting types" do
    query_parser = Rack::QueryParser.make_default(32)
    proc { query_parser.parse_nested_query_strict("a[]=1&a[b]=2") }.
      must_raise Rack::QueryParser::ParameterTypeError
    proc { query_parser.parse_nested_query_strict("a[b]=1&a[]=2") }.
      must_raise Rack::QueryParser::ParameterTypeError
  end

  it "strict mode raises InvalidParameterError for invalid byte sequences" do
    query_parser = Rack::QueryParser.make_default(32)
    proc { query_parser.parse_nested_query_strict("a=%y") }.
      must_raise Rack::QueryParser::InvalidParameterError
  end

  it "strict mode enforces the same limits as the default mode" do
    query_parser = Rack::QueryParser.make_default(2)
    query_parser.parse_nested_query_strict("a[b]=1").params.must_equal({"a" => {"b" => "1"}})
    proc { query_parser.parse_nested_query_strict("a[b][c]=1") }.
      must_raise Rack::QueryParser::QueryLimitError

    query_parser = Rack::QueryParser.make_default(32, bytesize_limit: 3)
    query_parser.parse_nested_query_strict("a=a").params.must_equal({"a" => "a"})
    proc { query_parser.parse_nested_query_strict("a=aa") }.
      must_raise Rack::QueryParser::QueryLimitError

    query_parser = Rack::QueryParser.make_default(32, params_limit: 2)
    query_parser.parse_nested_query_strict("a=a&b=b").params.must_equal({"a" => "a", "b" => "b"})
    proc { query_parser.parse_nested_query_strict("a=a&b=b&c=c") }.
      must_raise Rack::QueryParser::QueryLimitError
  end

  it "strict mode merges results from multiple sources" do
    query_parser = Rack::QueryParser.make_default(32)
    get = query_parser.parse_nested_query_strict("a[b]=1&c=1", '&', source: 'query string')
    post = query_parser.parse_nested_query_strict("a[d]=2&e[]=1", '&', source: 'request body')
    merged = get.merge(post)
    merged.params.must_equal({"a" => {"b" => "1", "d" => "2"}, "c" => "1", "e" => ["1"]})
    merged.leaves.size.must_equal 4
    merged.leaf_at(["a", "b"]).raw_key.must_equal "a[b]"
    merged.leaf_at(["a"]).raw_key.must_equal "a[b]"
    merged.leaf_at(["missing"]).must_be_nil
  end

  it "strict mode merge concatenates arrays from both sources" do
    query_parser = Rack::QueryParser.make_default(32)
    get = query_parser.parse_nested_query_strict("a[]=1", '&', source: 'query string')
    post = query_parser.parse_nested_query_strict("a[]=2", '&', source: 'request body')
    get.merge(post).params.must_equal({"a" => ["1", "2"]})
  end

  it "strict mode merge reports both sources on conflict" do
    query_parser = Rack::QueryParser.make_default(32)
    get = query_parser.parse_nested_query_strict("a[b]=1", '&', source: 'query string')
    post = query_parser.parse_nested_query_strict("a[b]=2", '&', source: 'request body')
    error = proc { get.merge(post) }.must_raise Rack::QueryParser::ParameterConflictError
    error.message.must_include "conflicting assignments for parameter `a[b]'"
    error.message.must_include "in query string"
    error.message.must_include "in request body"
  end

  it "strict mode merge rejects scalar assignments over structured parameters" do
    query_parser = Rack::QueryParser.make_default(32)
    get = query_parser.parse_nested_query_strict("a[b]=1", '&', source: 'query string')
    post = query_parser.parse_nested_query_strict("a=2", '&', source: 'request body')
    proc { get.merge(post) }.must_raise Rack::QueryParser::ParameterConflictError
  end

  it "normalize_pairs_strict detects conflicts without byte ranges" do
    query_parser = Rack::QueryParser.make_default(32)
    result = query_parser.normalize_pairs_strict([["a[b]", "1"], ["a[c]", "2"]], source: 'multipart form')
    result.params.must_equal({"a" => {"b" => "1", "c" => "2"}})
    result.leaves.map(&:byte_range).must_equal [nil, nil]
    result.leaves.map(&:source).must_equal ["multipart form", "multipart form"]
    error = proc { query_parser.normalize_pairs_strict([["a[b]", "1"], ["a[b]", "2"]], source: 'multipart form') }.
      must_raise Rack::QueryParser::ParameterConflictError
    error.message.must_include "multipart form"
  end

  it "default mode still silently keeps the last value for duplicate assignments" do
    query_parser = Rack::QueryParser.make_default(32)
    query_parser.parse_nested_query("a[b]=1&a%5Bb%5D=2").must_equal({"a" => {"b" => "2"}})
    query_parser.parse_nested_query("a=1&a=2").must_equal({"a" => "2"})
  end
end
