# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/structured_fields'
end

describe Rack::StructuredFields do
  SF = Rack::StructuredFields
  ParseError = SF::ParseError

  def decimal(value)
    SF::Decimal.new(BigDecimal(value))
  end

  def item(value, parameters = nil)
    SF::Item.new(value, parameters)
  end

  it 'parses and serializes RFC 8941 item vectors' do
    examples = {
      '?1' => true,
      '?0' => false,
      '19' => 19,
      '-19' => -19,
      '1.5' => decimal('1.5'),
      '-1.5' => decimal('-1.5'),
      '"hello world"' => 'hello world',
      '"say \"hi\""' => 'say "hi"',
      '"back\\\\slash"' => 'back\\slash',
      'foo' => SF::Token.new('foo'),
      'foo/1.2' => SF::Token.new('foo/1.2'),
      '*' => SF::Token.new('*'),
      ':YWJj:' => SF::ByteSequence.new('abc'),
      ':AQI:' => SF::ByteSequence.new("\x01\x02"),
      '::' => SF::ByteSequence.new(''),
      "\"a\tb\"" => "a\tb",
    }

    examples.each do |field, value|
      parsed = SF.parse_item(field)
      parsed.must_equal item(value)
      SF.serialize_item(parsed).must_equal field
    end
  end

  it 'preserves decimal precision instead of using Float' do
    parsed = SF.parse_item('1.234')
    parsed.value.must_equal decimal('1.234')
    parsed.value.class.must_equal SF::Decimal
    SF.serialize_item(parsed).must_equal '1.234'

    lambda { SF.serialize_item(1.234) }.must_raise SF::SerializationError
    lambda { SF.serialize_item(BigDecimal('1.2345')) }.must_raise SF::SerializationError
  end

  it 'parses item parameters with distinct value types' do
    parsed = SF.parse_item('foo; n=1; d=1.2; s="x"; t=bar; b=:YQ:; flag; bool=?0')

    parsed.must_equal item(
      SF::Token.new('foo'),
      {
        'n' => 1,
        'd' => decimal('1.2'),
        's' => 'x',
        't' => SF::Token.new('bar'),
        'b' => SF::ByteSequence.new('a'),
        'flag' => true,
        'bool' => false,
      }
    )
    SF.serialize_item(parsed).must_equal 'foo; n=1; d=1.2; s="x"; t=bar; b=:YQ:; flag; bool=?0'
  end

  it 'parses and serializes lists and inner lists' do
    field = 'sugar, tea; q=0.4, ("rum" *cream); mix=?1, 123'
    parsed = SF.parse_list(field)

    parsed.must_equal [
      item(SF::Token.new('sugar')),
      item(SF::Token.new('tea'), 'q' => decimal('0.4')),
      SF::InnerList.new([item('rum'), item(SF::Token.new('*cream'))], 'mix' => true),
      item(123),
    ]
    SF.serialize_list(parsed).must_equal 'sugar, tea; q=0.4, ("rum" *cream); mix, 123'
  end

  it 'parses and serializes dictionaries' do
    field = 'primary=1.230, nolist, list=(1 2); p="x", flag=?1, dup=1, dup=2; last=?1'
    parsed = SF.parse_dictionary(field)

    parsed.to_a.must_equal [
      ['primary', item(decimal('1.23'))],
      ['nolist', item(true)],
      ['list', SF::InnerList.new([item(1), item(2)], 'p' => 'x')],
      ['flag', item(true)],
      ['dup', item(2, 'last' => true)],
    ]
    SF.serialize_dictionary(parsed).must_equal 'primary=1.23, nolist, list=(1 2); p="x", flag, dup=2; last'
  end

  it 'keeps the first position when a repeated dictionary member is replaced' do
    parsed = SF.parse_dictionary('a=1, b=2, a=3')
    parsed.to_h.keys.must_equal %w[a b]
    parsed['a'].must_equal item(3)
  end

  it 'keeps the first position when a repeated parameter is replaced' do
    parameters = SF.parse_dictionary('x=1; a=1; b=2; a=3')['x'].parameters
    parameters.to_h.must_equal 'a' => 3, 'b' => 2
    parameters.map(&:first).must_equal %w[a b]
  end

  it 'does not rely on ordinary Hash equality for typed string values' do
    token = SF::Token.new('foo')
    bytes = SF::ByteSequence.new('foo')

    token.class.wont_equal String
    bytes.class.wont_equal String
    token.wont_equal 'foo'
    bytes.wont_equal 'foo'
    'foo'.wont_equal token
    'foo'.wont_equal bytes
    token.wont_equal bytes
    SF.serialize_item(token).must_equal 'foo'
    SF.serialize_item(bytes).must_equal ':Zm9v:'
  end

  it 'rejects integer and decimal range and precision violations' do
    valid_integers = %w[-999999999999999 999999999999999]
    invalid_numbers = %w[
      1000000000000000
      -1000000000000000
      9999999999999.0
      -9999999999999.0
      1.2345
      1.
      .5
      --1
      1-1
    ]

    valid_integers.each { |field| SF.parse_item(field) }
    invalid_numbers.each do |field|
      lambda { SF.parse_item(field) }.must_raise ParseError
    end
  end

  it 'rejects invalid strings, escapes, booleans, tokens and byte sequences' do
    invalid = %w[
      "hello
      "hello\x7f"
      "hello\xff"
      "hello\a"
      ?2
      :A===:
      :YW==:
    ]

    invalid.each do |field|
      lambda { SF.parse_item(field) }.must_raise ParseError
    end
  end

  it 'requires a space after a parameter semicolon' do
    SF.parse_item('x; a=1').must_equal item(SF::Token.new('x'), 'a' => 1)
    lambda { SF.parse_item('x;a=1') }.must_raise ParseError
  end

  it 'allows literal tabs but rejects invalid string escapes' do
    SF.parse_item("\"a\tb\"").value.must_equal "a\tb"
    lambda { SF.parse_item('"a\tb"') }.must_raise ParseError
  end

  it 'rejects illegal trailing characters for each explicit top-level type' do
    lambda { SF.parse_item('1,2') }.must_raise ParseError
    lambda { SF.parse_list('1,,2') }.must_raise ParseError
    lambda { SF.parse_list('1,') }.must_raise ParseError
    lambda { SF.parse_dictionary('a=1,') }.must_raise ParseError
    lambda { SF.parse_dictionary('A=1') }.must_raise ParseError
  end

  it 'joins repeated list and dictionary lines before parsing' do
    SF.parse_list(['1', '2']).must_equal [item(1), item(2)]
    SF.parse_dictionary(['a=1', 'b=2']).to_h.keys.must_equal %w[a b]
    lambda { SF.parse_item(['1', '2']) }.must_raise ParseError
  end

  it 'applies HTTP obs-fold continuation before parsing' do
    parsed = SF.parse_dictionary("a=1,\r\n b=2")
    parsed.to_h.keys.must_equal %w[a b]
  end

  it 'does not treat a bare line feed as HTTP line continuation' do
    lambda { SF.parse_list("1\n2") }.must_raise ParseError
    lambda { SF.parse_list(["1\n2"]) }.must_raise ParseError
  end

  it 'normalizes repeated members and explicit false when serializing' do
    SF.serialize_dictionary([['a', item(1)], ['a', item(2)]]).must_equal 'a=2'
    SF.serialize_item(item(SF::Token.new('x'), 'flag' => false)).must_equal 'x; flag=?0'
  end

  it 'leaves no half result when joined multiline input is invalid' do
    before = SF::Dictionary.new([['a', item(1)]])
    lambda { SF.parse_dictionary(['a=1', 'bad=']) }.must_raise ParseError
    before.to_a.must_equal [['a', item(1)]]
    before.frozen?.must_equal true
  end

  it 'freezes parsed value objects' do
    parsed = SF.parse_item('foo; a=1')
    parsed.frozen?.must_equal true
    parsed.value.frozen?.must_equal true
    parsed.parameters.frozen?.must_equal true
  end

  it 'round trips representative nested values' do
    value = {
      'number' => item(42),
      'decimal' => item(decimal('-0.0')),
      'nested' => SF::InnerList.new(
        [item(1), item(SF::Token.new('text'), 'x' => true)],
        'p' => SF::ByteSequence.new('ok')
      ),
    }
    field = SF.serialize_dictionary(value)
    field.must_equal 'number=42, decimal=-0.0, nested=(1 text; x); p=:b2s:'
    SF.serialize_dictionary(SF.parse_dictionary(field)).must_equal field
  end
end
