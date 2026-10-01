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

    # ParameterConflictError is the error that is raised in strict mode when
    # the same parameter path is assigned a value more than once, either
    # within a single input or when merging parameters from multiple sources
    # (such as the query string and the request body).
    class ParameterConflictError < ArgumentError
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

    # Leaf records a single scalar parameter assignment made while parsing in
    # strict mode. It keeps the parameter's normalized path, the raw (still
    # escaped) key as it appeared in the input, the byte range of the input
    # segment that produced the value, and the source of the input (such as
    # "query string" or "request body").
    class Leaf
      # The normalized parameter path as an array of segments, for example
      # ["a", "[]", "b"] for a parameter named "a[][b]".
      attr_accessor :path

      # The raw key as it appeared in the input, before unescaping.
      attr_reader :raw_key

      # The unescaped scalar value.
      attr_reader :value

      # The byte range of the "key=value" segment in the original input
      # string, or nil if the input was not available as a single string
      # (for example multipart form data).
      attr_reader :byte_range

      # A description of where the input came from, such as "query string"
      # or "request body".
      attr_reader :source

      def initialize(raw_key, value, byte_range, source)
        @raw_key = raw_key
        @value = value
        @byte_range = byte_range
        @source = source
      end

      # Human readable location of the input segment, used in error messages.
      def location
        loc = +"`#{raw_key}'"
        loc << " at bytes #{byte_range.begin}...#{byte_range.end}" if byte_range
        loc << " in #{source}" if source
        loc
      end
    end

    # StrictResult is the result of parsing parameters in strict mode. It
    # combines the nested parameter hash with the list of Leaf entries
    # describing the origin of each scalar value.
    class StrictResult
      # The nested parameter hash, same as parse_nested_query would return.
      attr_reader :params

      # The Leaf entries for all scalar values, in input order.
      attr_reader :leaves

      def initialize(params, leaves)
        @params = params
        @leaves = leaves
      end

      def to_h
        @params
      end

      # Returns the first leaf at or below the given parameter path.
      def leaf_at(path)
        @leaves.find { |leaf| leaf.path && leaf.path[0, path.length] == path }
      end

      # Merge another StrictResult into this one, combining parameters from
      # two sources (such as the query string and the request body). Hash
      # values are merged recursively and array values are concatenated. If
      # both results assign a value to the same scalar path, a
      # ParameterConflictError is raised identifying both input segments.
      def merge(other)
        StrictResult.new(merge_values(@params, other.params, [], other), @leaves + other.leaves)
      end

      private

      def merge_values(left, right, path, other)
        if left.is_a?(Hash) && right.is_a?(Hash)
          merged = left.dup
          right.each_pair do |key, value|
            merged[key] = merged.key?(key) ? merge_values(merged[key], value, path + [key], other) : value
          end
          merged
        elsif left.is_a?(Array) && right.is_a?(Array)
          left + right
        else
          previous = leaf_at(path)
          current = other.leaf_at(path)
          raise ParameterConflictError,
            "conflicting assignments for parameter `#{QueryParser.format_param_path(path)}': " \
            "#{current ? current.location : 'a value'} conflicts with #{previous ? previous.location : 'an earlier value'}"
        end
      end
    end

    # StrictContext tracks parameter assignments during strict parsing. It
    # records, for each params hash, which keys have been assigned and which
    # Leaf caused the assignment, so that duplicate assignments can be
    # detected and reported with both input segments.
    class StrictContext
      attr_reader :leaves

      def initialize
        @assignments = {}.compare_by_identity
        @leaves = []
      end

      # Records that +leaf+ assigned +key+ in +hash+. Structural assignments
      # (creation of an Array or Hash container) do not override existing
      # records and do not add to the leaf list; the leaf is recorded when
      # its scalar value is stored.
      def record(hash, key, leaf, structural: false)
        keys = (@assignments[hash] ||= {})
        if structural
          keys[key] ||= leaf
        else
          keys[key] = leaf
          add_leaf(leaf)
        end
      end

      # Records a scalar leaf that does not assign a hash key (an array
      # element).
      def add_leaf(leaf)
        @leaves << leaf
      end

      # Returns the Leaf that previously assigned +key+ in +hash+, if any.
      def previous_assignment(hash, key)
        if keys = @assignments[hash]
          keys[key]
        end
      end
    end
    private_constant :StrictContext

    # ParamsTooDeepError is the old name for the error that is raised when params
    # are recursively nested over the specified limit. Make it the same as
    # as QueryLimitError, so that code that rescues ParamsTooDeepError error
    # to handle bad query strings also now handles other limits.
    ParamsTooDeepError = QueryLimitError

    def self.make_default(param_depth_limit, **options)
      new(Params, param_depth_limit, **options)
    end

    # Formats a parameter path (array of segments) in canonical bracket
    # notation, for example ["a", "[]", "b"] becomes "a[][b]".
    def self.format_param_path(segments)
      segments.map.with_index do |segment, i|
        if i == 0 || segment == '[]'
          segment
        else
          "[#{segment}]"
        end
      end.join
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

    # parse_nested_query_strict expands a query string into structural types
    # like parse_nested_query, but additionally tracks the origin of every
    # scalar value and refuses ambiguous input. It returns a StrictResult
    # combining the nested parameters with Leaf entries recording each scalar
    # value's raw key and byte range in the input.
    #
    # Unlike parse_nested_query, assigning a value to the same parameter path
    # twice (for example "a[b]=1&a%5Bb%5D=2", where percent-encoding hides the
    # duplicate) raises ParameterConflictError instead of silently keeping the
    # last value. Appending to arrays ("a[]=1&a[]=2") remains valid, and
    # hashes inside arrays are tracked by the array element they belong to,
    # so "a[][b]=1&a[][b]=2" (two separate array elements) is also valid.
    #
    # The optional source argument describes where the input came from (such
    # as "query string" or "request body") and is included in conflict error
    # messages. The same bytesize, params, and depth limits as in the default
    # mode apply.
    def parse_nested_query_strict(qs, separator = nil, source: nil)
      params = make_params
      context = StrictContext.new

      each_query_pair_with_offsets(qs, separator) do |raw_key, key, value, byte_range|
        leaf = Leaf.new(raw_key, value, byte_range, source)
        _normalize_params_strict(params, key, value, 0, [], context, leaf)
      end

      StrictResult.new(params.to_h, context.leaves)
    end

    # normalize_pairs_strict builds a StrictResult from an array of already
    # split [key, value] pairs, applying the same conflict detection as
    # parse_nested_query_strict. It is useful for input that is not available
    # as a single encoded string (such as multipart form data), so no byte
    # ranges are recorded for the leaves.
    def normalize_pairs_strict(pairs, source: nil)
      params = make_params
      context = StrictContext.new

      pairs.each do |key, value|
        leaf = Leaf.new(key, value, nil, source)
        _normalize_params_strict(params, key, value, 0, [], context, leaf)
      end

      StrictResult.new(params.to_h, context.leaves)
    end

    # normalize_params recursively expands parameters into structural types. If
    # the structural types represented by two different parameter names are in
    # conflict, a ParameterTypeError is raised.  The depth argument is deprecated
    # and should no longer be used, it is kept for backwards compatibility with
    # earlier versions of rack.
    def normalize_params(params, name, v, _depth=nil)
      _normalize_params(params, name, v, 0)
    end

    private def _normalize_params(params, name, v, depth)
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
          return [v]
        else
          params[k] = v
        end
      elsif after == "["
        params[name] = v
      elsif after == "[]"
        params[k] ||= []
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        params[k] << v
      elsif after.start_with?('[]')
        # Recognize x[][y] (hash inside array) parameters
        unless after[2] == '[' && after.end_with?(']') && (child_key = after[3, after.length-4]) && !child_key.empty? && !child_key.index('[') && !child_key.index(']')
          # Handle other nested array parameters
          child_key = after[2, after.length]
        end
        params[k] ||= []
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        if params_hash_type?(params[k].last) && !params_hash_has_key?(params[k].last, child_key)
          _normalize_params(params[k].last, child_key, v, depth + 1)
        else
          params[k] << _normalize_params(make_params, child_key, v, depth + 1)
        end
      else
        params[k] ||= make_params
        raise ParameterTypeError, "expected Hash (got #{params[k].class.name}) for param `#{k}'" unless params_hash_type?(params[k])
        params[k] = _normalize_params(params[k], after, v, depth + 1)
      end

      params
    rescue Encoding::CompatibilityError
      raise IncompatibleEncodingError
    end

    # Strict variant of _normalize_params. Behaves like _normalize_params,
    # but records every assignment in the given StrictContext and raises
    # ParameterConflictError when a scalar value is stored at a key that has
    # already been assigned in the same params hash. The path argument holds
    # the normalized parameter path segments leading to the current params
    # hash, and leaf describes the input segment being processed.
    private def _normalize_params_strict(params, name, v, depth, path, context, leaf)
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
          leaf.path = path + [k]
          context.add_leaf(leaf)
          return [v]
        else
          store_strict_scalar(params, k, v, path + [k], context, leaf)
        end
      elsif after == "["
        store_strict_scalar(params, name, v, path + [name], context, leaf)
      elsif after == "[]"
        params[k] ||= []
        context.record(params, k, leaf, structural: true)
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        params[k] << v
        leaf.path = path + [k, '[]']
        context.add_leaf(leaf)
      elsif after.start_with?('[]')
        # Recognize x[][y] (hash inside array) parameters
        unless after[2] == '[' && after.end_with?(']') && (child_key = after[3, after.length-4]) && !child_key.empty? && !child_key.index('[') && !child_key.index(']')
          # Handle other nested array parameters
          child_key = after[2, after.length]
        end
        params[k] ||= []
        context.record(params, k, leaf, structural: true)
        raise ParameterTypeError, "expected Array (got #{params[k].class.name}) for param `#{k}'" unless params[k].is_a?(Array)
        if params_hash_type?(params[k].last) && !params_hash_has_key?(params[k].last, child_key)
          _normalize_params_strict(params[k].last, child_key, v, depth + 1, path + [k, '[]'], context, leaf)
        else
          params[k] << _normalize_params_strict(make_params, child_key, v, depth + 1, path + [k, '[]'], context, leaf)
        end
      else
        params[k] ||= make_params
        context.record(params, k, leaf, structural: true)
        raise ParameterTypeError, "expected Hash (got #{params[k].class.name}) for param `#{k}'" unless params_hash_type?(params[k])
        params[k] = _normalize_params_strict(params[k], after, v, depth + 1, path + [k], context, leaf)
      end

      params
    rescue Encoding::CompatibilityError
      raise IncompatibleEncodingError
    end

    # Stores a scalar value in strict mode, raising ParameterConflictError if
    # the key has already been assigned in the same params hash.
    private def store_strict_scalar(params, key, value, path, context, leaf)
      leaf.path = path
      if previous = context.previous_assignment(params, key)
        raise ParameterConflictError,
          "duplicate assignment for parameter `#{QueryParser.format_param_path(path)}': " \
          "#{leaf.location} conflicts with #{previous.location}"
      end
      params[key] = value
      context.record(params, key, leaf)
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
      return if !qs || qs.empty?

      if @bytesize_limit && qs.bytesize > @bytesize_limit
        raise QueryLimitError, "total query size exceeds limit (#{@bytesize_limit})"
      end

      sep = separator ? (COMMON_SEP[separator] || /[#{separator}] */n) : DEFAULT_SEP
      pairs = @params_limit ? qs.split(sep, @params_limit + 1) : qs.split(sep)

      if @params_limit && pairs.size > @params_limit
        param_count = pairs.size + pairs.last.count(separator || "&")
        raise QueryLimitError, "total number of query parameters (#{param_count}) exceeds limit (#{@params_limit})"
      end

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

    # Splits a query string into pairs like each_query_pair, but additionally
    # yields the raw (still escaped) key and the byte range of the pair in
    # the original string, so strict mode can record where each value came
    # from. Enforces the same bytesize and params limits as each_query_pair.
    private def each_query_pair_with_offsets(qs, separator)
      return if !qs || qs.empty?

      if @bytesize_limit && qs.bytesize > @bytesize_limit
        raise QueryLimitError, "total query size exceeds limit (#{@bytesize_limit})"
      end

      sep = separator ? (COMMON_SEP[separator] || /[#{separator}] */n) : DEFAULT_SEP

      # Byte offsets are computed on a binary copy so that multibyte
      # characters in the input do not skew the ranges.
      binary = qs.b
      ranges = []
      pos = 0
      # Emulate String#split with a limit of params_limit + 1 fields, keeping
      # track of the byte range of each field.
      while (!@params_limit || ranges.size < @params_limit) && (match = binary.match(sep, pos))
        ranges << (pos...match.begin(0))
        pos = match.end(0)
      end
      ranges << (pos...binary.bytesize)

      if @params_limit && ranges.size > @params_limit
        param_count = ranges.size + binary[ranges.last].count(separator || "&")
        raise QueryLimitError, "total number of query parameters (#{param_count}) exceeds limit (#{@params_limit})"
      end

      ranges.each do |range|
        pair = qs.byteslice(range)
        next if pair.nil? || pair.empty?
        raw_key, value = pair.split('=', 2)
        key = unescape(raw_key)
        value = unescape(value) if value
        yield raw_key, key, value, range
      end
    rescue ArgumentError => e
      raise if e.is_a?(ParameterConflictError)
      raise InvalidParameterError, e.message, e.backtrace
    end

    def unescape(string, encoding = Encoding::UTF_8)
      URI.decode_www_form_component(string, encoding)
    end

    class Params < Hash
      alias_method :to_params_hash, :to_h
    end
  end
end
