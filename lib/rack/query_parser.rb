# frozen_string_literal: true

require_relative 'bad_request'
require 'uri'

module Rack
  class QueryParser
    DEFAULT_SEP = /& */n
    COMMON_SEP = { ";" => /; */n, ";," => /[;,] */n, "&" => /& */n }

    # ParameterTypeError is the error that is raised when incoming structural
    # parameters (parsed by parse_nested_query) contain conflicting types.
    class ParameterTypeError < TypeError
      include BadRequest
    end

    # InvalidParameterError is the error that is raised when incoming structural
    # parameters (parsed by parse_nested_query) contain invalid format or byte
    # sequence.
    class InvalidParameterError < ArgumentError
      include BadRequest
    end

    # QueryLimitError is for errors raised when the query provided exceeds one
    # of the query parser limits.
    class QueryLimitError < RangeError
      include BadRequest
    end

    class IncompatibleEncodingError < EncodingError
      include BadRequest
    end

    # AmbiguousParameterError is the error raised by strict query parsing
    # (see #parse_nested_query_strict) when the same parameter path is
    # assigned a value more than once, which would silently discard one of
    # the values when parsing in non-strict mode.
    class AmbiguousParameterError < InvalidParameterError
      def initialize(path, first, second)
        @path = path
        @first = first
        @second = second
        super("conflicting assignments for parameter `#{AmbiguousParameterError.format_path(path)}': #{AmbiguousParameterError.describe_leaf(first)} and #{AmbiguousParameterError.describe_leaf(second)}")
      end

      # The parameter path that was assigned more than once, as an array of
      # segments (strings for hash keys, integers for array indices).
      attr_reader :path

      # The Leaf objects for the two conflicting assignments.
      attr_reader :first, :second

      def self.format_path(path)
        path.inject(+'') do |string, segment|
          if string.empty?
            string << segment.to_s
          else
            string << '[' << segment.to_s << ']'
          end
        end
      end

      def self.describe_leaf(leaf)
        leaf ? leaf.describe : 'no recorded input'
      end
    end

    # Leaf records the origin of a single scalar parameter value found while
    # parsing in strict mode: where it ended up in the nested structure, and
    # where it came from in the original input.
    Leaf = Struct.new(:path, :key, :value, :raw, :range, :source) do
      # The parameter path of the leaf, as an array of segments (strings for
      # hash keys, integers for array indices, '[]' for array elements whose
      # index is not known).

      # The unescaped parameter key as parsed, for example "a[b]".

      # The raw input segment the value came from, for example "a%5Bb%5D=2".

      # The byte range of the raw segment in the original input string.

      # A label identifying the input the value came from (for example
      # "query string" or "form body"), or nil if no label was given.

      # The key exactly as it appeared in the original input, before
      # unescaping, for example "a%5Bb%5D".
      def raw_key
        raw.split('=', 2).first
      end

      # A human readable description of where the value came from, suitable
      # for inclusion in error messages.
      def describe
        location = "bytes #{range.begin}...#{range.end}"
        location = "#{source}, #{location}" if source
        "`#{raw}' (#{location})"
      end
    end

    # StrictResult is the result of QueryParser#parse_nested_query_strict.
    # It exposes the parsed parameters together with a Leaf for every scalar
    # value, recording the original key and byte range the value came from.
    # Two results can be combined with #merge, which reports conflicts
    # between the two inputs (such as a query string and a form body)
    # instead of silently keeping only one of the values.
    class StrictResult
      # The parsed parameters, with the same structure as the return value
      # of #parse_nested_query.
      attr_reader :params

      # The Leaf for every scalar value in #params, in input order.
      attr_reader :leaves

      # The label identifying the input these parameters were parsed from.
      attr_reader :source

      def initialize(params, leaves, source, params_class)
        @params = params
        @leaves = leaves
        @source = source
        @params_class = params_class
      end

      def to_h
        @params.to_h
      end

      def [](key)
        @params[key]
      end

      def key?(key)
        @params.key?(key)
      end

      # Merges this result with another StrictResult, such as the result of
      # parsing a form body, and returns a new StrictResult. Hashes are
      # merged recursively and arrays are concatenated, mirroring how
      # repeated parameters combine within a single input. If both inputs
      # assign a value to the same parameter path, an
      # AmbiguousParameterError is raised identifying both sources, instead
      # of silently keeping only the last value.
      def merge(other)
        merged = merge_params(@params, other.params, [], @leaves, other.leaves)
        StrictResult.new(merged, @leaves + other.leaves, @source, @params_class)
      end

      private

      def merge_params(left, right, path, left_leaves, right_leaves)
        merged = left.dup
        right.each do |key, value|
          if merged.key?(key)
            merged[key] = merge_value(merged[key], value, path + [key], left_leaves, right_leaves)
          else
            merged[key] = value
          end
        end
        merged
      end

      def merge_value(left, right, path, left_leaves, right_leaves)
        if left.is_a?(@params_class) && right.is_a?(@params_class)
          merge_params(left, right, path, left_leaves, right_leaves)
        elsif left.is_a?(Array) && right.is_a?(Array)
          left + right
        else
          first = left_leaves.find { |leaf| leaf.path[0, path.size] == path }
          second = right_leaves.find { |leaf| leaf.path[0, path.size] == path }
          raise AmbiguousParameterError.new(path, first, second)
        end
      end
    end

    # ParamsTooDeepError is the old name for the error that is raised when params
    # are recursively nested over the specified limit. Make it the same as
    # as QueryLimitError, so that code that rescues ParamsTooDeepError error
    # to handle bad query strings also now handles other limits.
    ParamsTooDeepError = QueryLimitError

    def self.make_default(param_depth_limit, **options)
      new(Params, param_depth_limit, **options)
    end

    attr_reader :param_depth_limit

    env_int = lambda do |key, val|
      if str_val = ENV[key]
        begin
          val = Integer(str_val, 10)
        rescue ArgumentError
          raise ArgumentError, "non-integer value provided for environment variable #{key}"
        end
      end

      val if val >= 0
    end

    BYTESIZE_LIMIT = env_int.call("RACK_QUERY_PARSER_BYTESIZE_LIMIT", 4194304)
    private_constant :BYTESIZE_LIMIT

    PARAMS_LIMIT = env_int.call("RACK_QUERY_PARSER_PARAMS_LIMIT", 4096)
    private_constant :PARAMS_LIMIT

    attr_reader :bytesize_limit

    def initialize(params_class, param_depth_limit, bytesize_limit: BYTESIZE_LIMIT, params_limit: PARAMS_LIMIT)
      @params_class = params_class
      @param_depth_limit = param_depth_limit
      @bytesize_limit = bytesize_limit
      @params_limit = params_limit
    end

    # Stolen from Mongrel, with some small modifications:
    # Parses a query string by breaking it up at the '&'.  You can also use this
    # to parse cookies by changing the characters used in the second parameter
    # (which defaults to '&').
    def parse_query(qs, separator = nil, &unescaper)
      params = make_params

      each_query_pair(qs, separator, unescaper) do |k, v|
        if cur = params[k]
          if cur.class == Array
            params[k] << v
          else
            params[k] = [cur, v]
          end
        else
          params[k] = v
        end
      end

      return params.to_h
    end

    # Parses a query string by breaking it up at the '&', returning all key-value
    # pairs as an array of [key, value] arrays. Unlike parse_query, this preserves
    # all duplicate keys rather than collapsing them.
    def parse_query_pairs(qs, separator = nil)
      pairs = []

      each_query_pair(qs, separator) do |k, v|
        pairs << [k, v]
      end

      pairs
    end

    # parse_nested_query expands a query string into structural types. Supported
    # types are Arrays, Hashes and basic value types. It is possible to supply
    # query strings with parameters of conflicting types, in this case a
    # ParameterTypeError is raised. Users are encouraged to return a 400 in this
    # case.
    def parse_nested_query(qs, separator = nil)
      params = make_params

      each_query_pair(qs, separator) do |k, v|
        _normalize_params(params, k, v, 0)
      end

      return params.to_h
    end

    # Parses a query string like #parse_nested_query, but in strict mode:
    # the returned StrictResult records a Leaf for every scalar value,
    # keeping the original key and byte range the value came from, and an
    # AmbiguousParameterError is raised if the same parameter path is
    # assigned a value more than once (for example "a[b]=1&a[b]=2", or
    # "a[b]=1&a%5Bb%5D=2" where both keys unescape to the same path).
    # Appending to an array remains legal ("a[]=1&a[]=2"), and values
    # inside arrays are attributed to the array element they actually
    # belong to when detecting conflicts.
    #
    # The optional source argument labels the input (for example "query
    # string"), so that errors raised when merging results from different
    # inputs can identify where each conflicting value came from.
    #
    # The configured depth, bytesize and parameter count limits are
    # enforced the same way as in #parse_nested_query.
    def parse_nested_query_strict(qs, separator = nil, source: nil)
      params = make_params
      context = StrictContext.new(source)

      each_query_pair_with_spans(qs, separator) do |k, v, raw, range|
        context.pair(k, raw, range)
        _normalize_params(params, k, v, 0, context, [])
      end

      StrictResult.new(params, context.leaves, source, @params_class)
    end

    # normalize_params recursively expands parameters into structural types. If
    # the structural types represented by two different parameter names are in
    # conflict, a ParameterTypeError is raised.  The depth argument is deprecated
    # and should no longer be used, it is kept for backwards compatibility with
    # earlier versions of rack.
    def normalize_params(params, name, v, _depth=nil)
      _normalize_params(params, name, v, 0)
    end

    private def _normalize_params(params, name, v, depth, context = nil, path = nil)
      raise ParamsTooDeepError if depth >= param_depth_limit

      if !name
        # nil name, treat same as empty string (required by tests)
        k = after = ''
      elsif depth == 0
        # Start of parsing, don't treat [] or [ at start of string specially
        if start = name.index('[', 1)
          # Start of parameter nesting, use part before brackets as key
          k = name[0, start]
          after = name[start, name.length]
        else
          # Plain parameter with no nesting
          k = name
          after = ''
        end
      elsif name.start_with?('[]')
        # Array nesting
        k = '[]'
        after = name[2, name.length]
      elsif name.start_with?('[') && (start = name.index(']', 1))
        # Hash nesting, use the part inside brackets as the key
        k = name[1, start-1]
        after = name[start+1, name.length]
      else
        # Probably malformed input, nested but not starting with [
        # treat full name as key for backwards compatibility.
        k = name
        after = ''
      end

      return if k.empty?

      if after == ''
        if k == '[]' && depth != 0
          context&.element(v, path + ['[]'])
          return [v]
        else
          context&.assign(params, k, v, path + [k])
          params[k] = v
        end
      elsif after == "["
        context&.assign(params, name, v, path + [name])
        params[name] = v
      elsif after == "[]"
        params[k] ||= []
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        params[k] << v
        context&.element(v, path + [k, params[k].length - 1])
      elsif after.start_with?('[]')
        # Recognize x[][y] (hash inside array) parameters
        unless after[2] == '[' && after.end_with?(']') && (child_key = after[3, after.length-4]) && !child_key.empty? && !child_key.index('[') && !child_key.index(']')
          # Handle other nested array parameters
          child_key = after[2, after.length]
        end
        params[k] ||= []
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        if params_hash_type?(params[k].last) && !params_hash_has_key?(params[k].last, child_key)
          _normalize_params(params[k].last, child_key, v, depth + 1, context, context && path + [k, params[k].length - 1])
        else
          params[k] << _normalize_params(make_params, child_key, v, depth + 1, context, context && path + [k, params[k].length])
        end
      else
        params[k] ||= make_params
        raise ParameterTypeError, "expected Hash (got #{params[k].class.name}) for param `#{k}'" unless params_hash_type?(params[k])
        params[k] = _normalize_params(params[k], after, v, depth + 1, context, context && path + [k])
      end

      params
    rescue Encoding::CompatibilityError
      raise IncompatibleEncodingError
    end

    def make_params
      @params_class.new
    end

    def new_depth_limit(param_depth_limit)
      self.class.new @params_class, param_depth_limit
    end

    private

    def params_hash_type?(obj)
      obj.kind_of?(@params_class)
    end

    def params_hash_has_key?(hash, key)
      return false if /\[\]/.match?(key)

      key.split(/[\[\]]+/).inject(hash) do |h, part|
        next h if part == ''
        return false unless params_hash_type?(h) && h.key?(part)
        h[part]
      end

      true
    end

    def each_query_pair(qs, separator, unescaper = nil)
      pairs = split_query_pairs(qs, separator)

      if unescaper
        pairs.each do |p|
          next if p.empty?
          k, v = p.split('=', 2).map!(&unescaper)
          yield k, v
        end
      else
        pairs.each do |p|
          next if p.empty?
          k, v = p.split('=', 2).map! { |s| unescape(s) }
          yield k, v
        end
      end
    rescue ArgumentError => e
      raise InvalidParameterError, e.message, e.backtrace
    end

    # Splits a query string into its raw pairs, enforcing the configured
    # bytesize and parameter count limits.
    def split_query_pairs(qs, separator)
      return [] if !qs || qs.empty?

      if @bytesize_limit && qs.bytesize > @bytesize_limit
        raise QueryLimitError, "total query size exceeds limit (#{@bytesize_limit})"
      end

      sep = separator ? (COMMON_SEP[separator] || /[#{separator}] */n) : DEFAULT_SEP
      pairs = @params_limit ? qs.split(sep, @params_limit + 1) : qs.split(sep)

      if @params_limit && pairs.size > @params_limit
        param_count = pairs.size + pairs.last.count(separator || "&")
        raise QueryLimitError, "total number of query parameters (#{param_count}) exceeds limit (#{@params_limit})"
      end

      pairs
    end

    # Like each_query_pair, but additionally yields the raw pair text and
    # the byte range it occupies in the original query string, so that
    # strict parsing can record where each value came from.
    def each_query_pair_with_spans(qs, separator)
      pairs = split_query_pairs(qs, separator)
      return if pairs.empty?

      binary = qs.b
      pos = 0
      pairs.each do |p|
        next if p.empty?
        start = binary.index(p.b, pos)
        finish = start + p.bytesize
        pos = finish
        k, v = p.split('=', 2).map! { |s| unescape(s) }
        yield k, v, p, start...finish
      end
    rescue ArgumentError => e
      raise if e.is_a?(InvalidParameterError)
      raise InvalidParameterError, e.message, e.backtrace
    end

    def unescape(string, encoding = Encoding::UTF_8)
      URI.decode_www_form_component(string, encoding)
    end

    # StrictContext tracks the origin of every leaf value while parsing in
    # strict mode, and raises AmbiguousParameterError when a parameter path
    # that already holds a value is assigned again.
    class StrictContext # :nodoc:
      def initialize(source)
        @source = source
        @leaves = []
        @assignments = {}
        @key = @raw = @range = nil
      end

      attr_reader :leaves

      # Called before normalizing each pair, to record which input segment
      # is currently being processed.
      def pair(key, raw, range)
        @key = key
        @raw = raw
        @range = range
      end

      # Records a scalar value assigned to params[key], raising
      # AmbiguousParameterError if the slot already holds a value.
      def assign(params, key, value, path)
        if (prior = @assignments[[params.object_id, key]])
          raise AmbiguousParameterError.new(path, prior, leaf(value, path))
        elsif params.key?(key)
          # A structure built by earlier input is silently replaced by a
          # scalar in non-strict mode; point at a leaf inside it.
          prior = @leaves.find { |l| l.path[0, path.size] == path }
          raise AmbiguousParameterError.new(path, prior, leaf(value, path))
        end

        record = leaf(value, path)
        @assignments[[params.object_id, key]] = record
        @leaves << record
      end

      # Records a scalar value appended to an array, which never conflicts.
      def element(value, path)
        @leaves << leaf(value, path)
      end

      private

      def leaf(value, path)
        Leaf.new(path, @key, value, @raw, @range, @source)
      end
    end

    class Params < Hash
      alias_method :to_params_hash, :to_h
    end
  end
end
