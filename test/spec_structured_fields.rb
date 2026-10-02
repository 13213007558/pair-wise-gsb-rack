# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/structured_fields'
end

describe Rack::StructuredFields do
  let(:sf) { Rack::StructuredFields }
  let(:decimal) { Rack::StructuredFields::Decimal }
  let(:token) { Rack::StructuredFields::Token }
  let(:byte_sequence) { Rack::StructuredFields::ByteSequence }
  let(:item) { Rack::StructuredFields::Item }
  let(:inner_list) { Rack::StructuredFields::InnerList }
  let(:parse_error) { Rack::StructuredFields::ParseError }
  let(:serialization_error) { Rack::StructuredFields::SerializationError }

  def parse_item_value(field)
    Rack::StructuredFields.parse_item(field).value
  end

  describe 'parsing items' do
    it 'parses integers' do
      parse_item_value('42').must_equal 42
      parse_item_value('-42').must_equal(-42)
      parse_item_value('0').must_equal 0
      parse_item_value('999999999999999').must_equal 999_999_999_999_999
      parse_item_value('-999999999999999').must_equal(-999_999_999_999_999)
    end

    it 'parses decimals as exact Decimal values' do
      value = parse_item_value('4.5')
      value.must_be_instance_of decimal
      value.value.must_equal Rational(9, 2)
      value.to_f.must_equal 4.5
      parse_item_value('1.500').value.must_equal Rational(3, 2)
      parse_item_value('-0.25').value.must_equal Rational(-1, 4)
      parse_item_value('2.0').value.must_equal 2
      parse_item_value('999999999999.999').value.must_equal Rational(999_999_999_999_999, 1000)
    end

    it 'parses strings with escapes' do
      parse_item_value('"hello world"').must_equal 'hello world'
      parse_item_value('""').must_equal ''
      parse_item_value('"a \"quoted\" string"').must_equal 'a "quoted" string'
      parse_item_value('"back\\\\slash"').must_equal 'back\\slash'
    end

    it 'parses tokens as Token instances' do
      value = parse_item_value('foo123/456')
      value.must_be_instance_of token
      value.must_equal 'foo123/456'
      parse_item_value('*').must_equal '*'
      parse_item_value('a:b').must_equal 'a:b'
    end

    it 'parses byte sequences as ByteSequence instances' do
      value = parse_item_value(':cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:')
      value.must_be_instance_of byte_sequence
      value.to_s.must_equal 'pretend this is binary content.'
      parse_item_value('::').to_s.must_equal ''
    end

    it 'parses booleans' do
      parse_item_value('?1').must_equal true
      parse_item_value('?0').must_equal false
    end

    it 'parses parameters' do
      parsed = sf.parse_item('"Applepie";flavor="vanilla";slices=8')
      parsed.value.must_equal 'Applepie'
      parsed.parameters.to_h.must_equal('flavor' => 'vanilla', 'slices' => 8)
    end

    it 'parses parameters without a value as true' do
      parsed = sf.parse_item('a;b')
      parsed.parameters.to_h.must_equal('b' => true)
    end

    it 'keeps parameter order' do
      sf.parse_item('a;z=1;y=2;x=3').parameters.keys.must_equal %w[z y x]
    end

    it 'ignores leading and trailing whitespace' do
      parse_item_value("  42 \t ").must_equal 42
    end

    it 'uses distinct types for numbers, tokens, strings, and byte sequences' do
      parse_item_value('1').must_be_instance_of Integer
      parse_item_value('1.0').must_be_instance_of decimal
      parse_item_value('"a"').must_be_instance_of String
      parse_item_value('a').must_be_instance_of token
      parse_item_value(':YQ==:').must_be_instance_of byte_sequence
    end
  end

  describe 'parsing lists' do
    it 'parses the RFC 8941 list example' do
      sf.parse_list('sugar, tea, rum').map(&:value).must_equal %w[sugar tea rum]
    end

    it 'parses the RFC 8941 inner list example' do
      list = sf.parse_list('("foo" "bar"), ("baz"), ("bat" "one"), ()')
      list.map(&:class).must_equal [inner_list, inner_list, inner_list, inner_list]
      list[0].map(&:value).must_equal %w[foo bar]
      list[1].map(&:value).must_equal %w[baz]
      list[2].map(&:value).must_equal %w[bat one]
      list[3].to_a.must_equal []
    end

    it 'parses an empty list' do
      sf.parse_list('').must_equal []
    end

    it 'parses members with parameters' do
      list = sf.parse_list('abc_123;a=1;b=2, def;g=?0')
      list[0].value.must_equal 'abc_123'
      list[0].parameters.to_h.must_equal('a' => 1, 'b' => 2)
      list[1].parameters.to_h.must_equal('g' => false)
    end

    it 'parses inner lists with parameters' do
      list = sf.parse_list('("a";p=1 "b");q=:YQ==:')
      list[0].parameters.to_h.must_equal('q' => byte_sequence.new('a'))
      list[0][0].parameters.to_h.must_equal('p' => 1)
    end
  end

  describe 'parsing dictionaries' do
    it 'parses the RFC 8941 dictionary example' do
      dict = sf.parse_dictionary('en="Applepie", da=:w4ZibGV0w6ZydGU=:')
      dict.keys.must_equal %w[en da]
      dict['en'].value.must_equal 'Applepie'
      dict['da'].value.must_equal byte_sequence.new("\xc3\x86blet\xc3\xa6rte".b)
    end

    it 'parses members without a value as true' do
      dict = sf.parse_dictionary('a, b=?0, c=1')
      dict['a'].value.must_equal true
      dict['b'].value.must_equal false
      dict['c'].value.must_equal 1
    end

    it 'parses parameters on valueless members' do
      dict = sf.parse_dictionary('a;p=?1')
      dict['a'].value.must_equal true
      dict['a'].parameters.to_h.must_equal('p' => true)
    end

    it 'parses inner list members' do
      dict = sf.parse_dictionary('a=(1 2), b=()')
      dict['a'].must_be_instance_of inner_list
      dict['a'].map(&:value).must_equal [1, 2]
      dict['b'].to_a.must_equal []
    end

    it 'parses an empty dictionary' do
      dict = sf.parse_dictionary('')
      dict.must_be_empty
      dict.size.must_equal 0
    end

    it 'keeps member order' do
      sf.parse_dictionary('z=1, y=2, x=3').keys.must_equal %w[z y x]
    end
  end

  describe 'parse errors' do
    it 'rejects trailing characters' do
      proc { sf.parse_item('1 x') }.must_raise parse_error
      proc { sf.parse_item('1, 2') }.must_raise parse_error
      proc { sf.parse_list('1;2') }.must_raise parse_error
      proc { sf.parse_dictionary('a=1 b=2') }.must_raise parse_error
    end

    it 'rejects trailing and doubled commas' do
      proc { sf.parse_list('1, 2,') }.must_raise parse_error
      proc { sf.parse_list('1,,2') }.must_raise parse_error
      proc { sf.parse_list(',1') }.must_raise parse_error
      proc { sf.parse_dictionary('a=1,') }.must_raise parse_error
    end

    it 'rejects invalid strings' do
      proc { sf.parse_item('"unterminated') }.must_raise parse_error
      proc { sf.parse_item('"bad \x escape"') }.must_raise parse_error
      proc { sf.parse_item("\"tab\tchar\"") }.must_raise parse_error
      proc { sf.parse_item('"del \x7f char"') }.must_raise parse_error
      proc { sf.parse_item('"non-ascii \xc3\xa9"'.b) }.must_raise parse_error
    end

    it 'rejects invalid numbers' do
      proc { sf.parse_item('1.') }.must_raise parse_error
      proc { sf.parse_item('1.2345') }.must_raise parse_error
      proc { sf.parse_item('1234567890123.1') }.must_raise parse_error
      proc { sf.parse_item('1234567890123456') }.must_raise parse_error
      proc { sf.parse_item('9999999999999999') }.must_raise parse_error
      proc { sf.parse_item('-9999999999999999') }.must_raise parse_error
      proc { sf.parse_item('-') }.must_raise parse_error
    end

    it 'rejects invalid booleans, tokens, and byte sequences' do
      proc { sf.parse_item('?2') }.must_raise parse_error
      proc { sf.parse_item('?') }.must_raise parse_error
      proc { sf.parse_item(':aGVsbG8!:' ) }.must_raise parse_error
      proc { sf.parse_item(':unterminated') }.must_raise parse_error
    end

    it 'rejects unterminated inner lists' do
      proc { sf.parse_list('(a b') }.must_raise parse_error
      proc { sf.parse_list('(a;b') }.must_raise parse_error
    end

    it 'rejects inner lists as top-level items' do
      proc { sf.parse_item('()') }.must_raise parse_error
      proc { sf.parse_item('(a)') }.must_raise parse_error
    end

    it 'rejects duplicate dictionary members' do
      proc { sf.parse_dictionary('a=1, a=2') }.must_raise parse_error
      proc { sf.parse_dictionary('a=1, b=2, a') }.must_raise parse_error
    end

    it 'rejects duplicate parameters' do
      proc { sf.parse_item('a;b=1;b=2') }.must_raise parse_error
      proc { sf.parse_item('a;b;b') }.must_raise parse_error
      proc { sf.parse_dictionary('a=(1);p=1;p=2') }.must_raise parse_error
    end

    it 'rejects invalid keys' do
      proc { sf.parse_dictionary('A=1') }.must_raise parse_error
      proc { sf.parse_dictionary('1a=1') }.must_raise parse_error
      proc { sf.parse_item('a;B=1') }.must_raise parse_error
    end

    it 'rejects empty input for items' do
      proc { sf.parse_item('') }.must_raise parse_error
      proc { sf.parse_item('   ') }.must_raise parse_error
    end
  end

  describe 'combining field lines' do
    it 'joins an array of field lines before parsing' do
      sf.parse_list(['sugar, tea', 'rum']).must_equal sf.parse_list('sugar, tea, rum')
      sf.parse_dictionary(['a=1', 'b=2']).keys.must_equal %w[a b]
    end

    it 'replaces obs-fold with a single space before parsing' do
      sf.parse_list("sugar,\r\n tea").must_equal sf.parse_list('sugar, tea')
      sf.parse_list("sugar,\r\n\ttea").must_equal sf.parse_list('sugar, tea')
    end

    it 'combines CRLF-separated lines in a single string' do
      sf.parse_list("sugar, tea\r\nrum").must_equal sf.parse_list('sugar, tea, rum')
    end

    it 'rejects nil, bare CR, and CR/LF inside array lines' do
      proc { sf.parse_list(nil) }.must_raise parse_error
      proc { sf.parse_list("a\rb") }.must_raise parse_error
      proc { sf.parse_list(["a\nb"]) }.must_raise parse_error
    end

    it 'fails the whole parse when any combined line is invalid' do
      proc { sf.parse_dictionary(['a=1', 'b=']) }.must_raise parse_error
      proc { sf.parse_dictionary(['a=1', 'a=2']) }.must_raise parse_error
      proc { sf.parse_item(['1', '2']) }.must_raise parse_error
    end

    it 'does not mutate the input on failure' do
      lines = ['a=1'.freeze, 'a=2'.freeze].freeze
      proc { sf.parse_dictionary(lines) }.must_raise parse_error
      lines.must_equal ['a=1', 'a=2']
    end
  end

  describe 'serializing' do
    it 'serializes bare items' do
      sf.serialize_item(42).must_equal '42'
      sf.serialize_item(-42).must_equal '-42'
      sf.serialize_item(decimal.new(Rational(3, 2))).must_equal '1.5'
      sf.serialize_item(decimal.new(2)).must_equal '2.0'
      sf.serialize_item(decimal.new(Rational(-1, 4))).must_equal '-0.25'
      sf.serialize_item('hello').must_equal '"hello"'
      sf.serialize_item(token.new('foo/bar')).must_equal 'foo/bar'
      sf.serialize_item(:token_symbol).must_equal 'token_symbol'
      sf.serialize_item(byte_sequence.new('hello')).must_equal ':aGVsbG8=:'
      sf.serialize_item(true).must_equal '?1'
      sf.serialize_item(false).must_equal '?0'
      sf.serialize_item(1.5).must_equal '1.5'
      sf.serialize_item(Rational(1, 8)).must_equal '0.125'
    end

    it 'escapes strings when serializing' do
      sf.serialize_item('a "quoted" \\ string').must_equal '"a \"quoted\" \\\\ string"'
    end

    it 'serializes items with parameters' do
      sf.serialize_item(item.new('a', 'b' => 1, 'c' => true)).must_equal '"a";b=1;c'
      sf.serialize_item(item.new(1, c: :d)).must_equal '1;c=d'
    end

    it 'serializes lists' do
      list = [item.new(token.new('sugar')), item.new(token.new('tea')), item.new(token.new('rum'))]
      sf.serialize_list(list).must_equal 'sugar, tea, rum'
      sf.serialize_list([]).must_equal ''
    end

    it 'serializes inner lists' do
      list = [inner_list.new(%w[foo bar]), inner_list.new(['baz']), inner_list.new([])]
      sf.serialize_list(list).must_equal '("foo" "bar"), ("baz"), ()'
    end

    it 'serializes dictionaries' do
      sf.serialize_dictionary('a' => 1, 'b' => false).must_equal 'a=1, b=?0'
      sf.serialize_dictionary('a' => true).must_equal 'a'
      sf.serialize_dictionary([['a', item.new(true, 'p' => 1)]]).must_equal 'a;p=1'
      sf.serialize_dictionary('a' => inner_list.new([1, 2])).must_equal 'a=(1 2)'
      sf.serialize_dictionary(sf.parse_dictionary('en="Applepie", da=:w4ZibGV0w6ZydGU=:')).
        must_equal 'en="Applepie", da=:w4ZibGV0w6ZydGU=:'
    end

    it 'rejects out of range integers' do
      proc { sf.serialize_item(1_000_000_000_000_000) }.must_raise serialization_error
      proc { sf.serialize_item(-1_000_000_000_000_000) }.must_raise serialization_error
      sf.serialize_item(999_999_999_999_999).must_equal '999999999999999'
    end

    it 'rejects decimals with too much precision or out of range' do
      proc { decimal.new(0.1) }.must_raise serialization_error
      proc { decimal.new(Rational(1, 10_000)) }.must_raise serialization_error
      proc { decimal.new(Rational(1_000_000_000_000)) }.must_raise serialization_error
      proc { sf.serialize_item(0.1) }.must_raise serialization_error
    end

    it 'rejects unserializable strings' do
      proc { sf.serialize_item("h\xc3\xa9llo") }.must_raise serialization_error
      proc { sf.serialize_item("bad\tstring") }.must_raise serialization_error
    end

    it 'rejects invalid tokens and keys' do
      proc { token.new('1bad') }.must_raise serialization_error
      proc { sf.serialize_item(item.new(1, 'Bad Key' => 2)) }.must_raise serialization_error
      proc { sf.serialize_dictionary('Bad' => 1) }.must_raise serialization_error
    end

    it 'rejects values of the wrong top-level type' do
      proc { sf.serialize_list('not a list') }.must_raise serialization_error
      proc { sf.serialize_dictionary(1) }.must_raise serialization_error
      proc { sf.serialize_item(Object.new) }.must_raise serialization_error
      proc { sf.serialize_item(inner_list.new([])) }.must_raise serialization_error
    end
  end

  describe 'round trips' do
    canonical = [
      '42', '-42', '4.5', '-0.25', '2.0', '?1', '?0',
      '"hello world"', '"a \"quoted\" string"', 'foo123/456', '*',
      ':cHJldGVuZCB0aGlzIGlzIGJpbmFyeSBjb250ZW50Lg==:', '::',
      '"Applepie";flavor="vanilla";slices=8', 'a;b',
    ]

    canonical.each do |field|
      it "round trips item #{field.inspect}" do
        sf.serialize_item(sf.parse_item(field)).must_equal field
      end
    end

    {
      'sugar, tea, rum' => :list,
      '("foo" "bar"), ("baz"), ("bat" "one"), ()' => :list,
      'abc_123;a=1;b=2, def;g=?0' => :list,
      'en="Applepie", da=:w4ZibGV0w6ZydGU=:' => :dictionary,
      'a=1, b=?0;foo=bar, c' => :dictionary,
      'a=(1 2), b=()' => :dictionary,
    }.each do |field, type|
      it "round trips #{type} #{field.inspect}" do
        parsed = sf.public_send("parse_#{type}", field)
        sf.public_send("serialize_#{type}", parsed).must_equal field
      end
    end

    it 'canonicalizes non-canonical input' do
      sf.serialize_item(sf.parse_item('1.500')).must_equal '1.5'
      sf.serialize_item(sf.parse_item('  42  ')).must_equal '42'
      sf.serialize_dictionary(sf.parse_dictionary('a=?1')).must_equal 'a'
      sf.serialize_item(sf.parse_item(':aGVsbG8:')).must_equal ':aGVsbG8=:'
    end
  end

  describe 'round trip properties' do
    let(:rng) { Random.new(8941) }

    def random_string(rng)
      Array.new(rng.rand(0..12)) { (0x20 + rng.rand(0x5f)).chr }.join
    end

    def random_token(rng)
      first = [*'a'..'z', *'A'..'Z', '*'].sample(random: rng)
      chars = [*'a'..'z', *'A'..'Z', *'0'..'9', *'!#$%&\'*+-.^_`|~:/'.chars]
      first + Array.new(rng.rand(0..10)) { chars.sample(random: rng) }.join
    end

    def random_key(rng)
      chars = [*'a'..'z', *'0'..'9', '_', '-', '.', '*']
      [*'a'..'z', '*'].sample(random: rng) +
        Array.new(rng.rand(0..7)) { chars.sample(random: rng) }.join
    end

    def random_bare_value(rng)
      case rng.rand(8)
      when 0
        rng.rand(-999_999_999_999_999..999_999_999_999_999)
      when 1
        rng.rand(-1000..1000)
      when 2
        scaled = rng.rand(-999_999_999_999_999..999_999_999_999_999)
        Rack::StructuredFields::Decimal.new(Rational(scaled, 1000))
      when 3
        random_string(rng)
      when 4
        Rack::StructuredFields::Token.new(random_token(rng))
      when 5
        bytes = Array.new(rng.rand(0..16)) { rng.rand(256) }.pack('C*')
        Rack::StructuredFields::ByteSequence.new(bytes)
      when 6
        true
      when 7
        false
      end
    end

    def random_parameters(rng)
      pairs = Array.new(rng.rand(0..3)) { random_key(rng) }.uniq.map do |key|
        [key, random_bare_value(rng)]
      end
      Rack::StructuredFields::Parameters.new(pairs)
    end

    def random_item(rng)
      Rack::StructuredFields::Item.new(random_bare_value(rng), random_parameters(rng))
    end

    def random_inner_list(rng)
      items = Array.new(rng.rand(0..4)) { random_item(rng) }
      Rack::StructuredFields::InnerList.new(items, random_parameters(rng))
    end

    def random_list(rng)
      Array.new(rng.rand(0..5)) do
        rng.rand(3) == 0 ? random_inner_list(rng) : random_item(rng)
      end
    end

    def random_dictionary(rng)
      pairs = Array.new(rng.rand(0..5)) { random_key(rng) }.uniq.map do |key|
        [key, rng.rand(3) == 0 ? random_inner_list(rng) : random_item(rng)]
      end
      Rack::StructuredFields::Dictionary.new(pairs)
    end

    it 'round trips random items' do
      200.times do
        value = random_item(rng)
        sf.parse_item(sf.serialize_item(value)).must_equal value
      end
    end

    it 'round trips random lists' do
      200.times do
        value = random_list(rng)
        sf.parse_list(sf.serialize_list(value)).must_equal value
      end
    end

    it 'round trips random dictionaries' do
      200.times do
        value = random_dictionary(rng)
        sf.parse_dictionary(sf.serialize_dictionary(value)).must_equal value
      end
    end

    it 'produces canonical, stable output' do
      100.times do
        serialized = sf.serialize_list(random_list(rng))
        sf.serialize_list(sf.parse_list(serialized)).must_equal serialized
      end
      100.times do
        serialized = sf.serialize_dictionary(random_dictionary(rng))
        sf.serialize_dictionary(sf.parse_dictionary(serialized)).must_equal serialized
      end
    end
  end
end
