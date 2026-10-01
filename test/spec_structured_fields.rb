# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/structured_fields'
end

describe Rack::StructuredFields do
  Item = Rack::StructuredFields::Item
  InnerList = Rack::StructuredFields::InnerList
  Decimal = Rack::StructuredFields::Decimal
  Token = Rack::StructuredFields::Token
  ByteSequence = Rack::StructuredFields::ByteSequence
  SFDate = Rack::StructuredFields::SFDate
  DisplayString = Rack::StructuredFields::DisplayString
  ParseError = Rack::StructuredFields::ParseError
  StructuredFieldError = Rack::StructuredFields::StructuredFieldError

  it 'parses and serializes every item type' do
    field = "\"comma, text\"; t=token; b=:aGVsbG8=:; flag; n=-7; d=1.5; at=@-123; y=?0; s=%\"caf\xC3\xA9,%20%25\"%".b
    value = Item.new(
      "comma, text",
      {
        "t" => Token.new("token"),
        "b" => ByteSequence.new("hello"),
        "flag" => true,
        "n" => -7,
        "d" => Decimal.new("1.50"),
        "at" => SFDate.new(-123),
        "y" => false,
        "s" => DisplayString.new("caf\xC3\xA9, %".b.force_encoding(Encoding::UTF_8))
      }
    )

    parsed = Rack::StructuredFields.parse_item(field)
    parsed.must_equal value
    canonical = '"comma, text";t=token;b=:aGVsbG8=:;flag;n=-7;d=1.5;at=@-123;y=?0;s=%"caf%C3%A9,%20%25"%'
    Rack::StructuredFields.serialize_item(parsed).must_equal canonical
  end

  it 'preserves inner lists, list items and nested parameters' do
    field = '"a,b", ("x" text/html); rel="a,b"; q=1.000, 3; n=4'
    value = [
      Item.new("a,b"),
      InnerList.new(
        [
          Item.new("x"),
          Item.new(Token.new("text/html"))
        ],
        {
          "rel" => "a,b",
        "q" => Decimal.new("1.000")
        }
      ),
      Item.new(3, { "n" => 4 })
    ]

    parsed = Rack::StructuredFields.parse_list(field)
    parsed.must_equal value
    Rack::StructuredFields.serialize_list(parsed).must_equal '"a,b", ("x" text/html);rel="a,b";q=1.0, 3;n=4'
  end

  it 'preserves a Signature-Input shaped dictionary' do
    field = 'sig1=(@1699794905 "@method" "@path" "x,y" "x-cafe" "");created=1699794905;alg="hmac", priority=?0'
    value = {
      "sig1" => InnerList.new(
        [
          Item.new(SFDate.new(1699794905)),
          Item.new("@method"),
          Item.new("@path"),
          Item.new("x,y"),
          Item.new("x-cafe"),
          Item.new("")
        ],
        {
          "created" => 1699794905,
          "alg" => "hmac"
        }
      ),
      "priority" => Item.new(false)
    }

    parsed = Rack::StructuredFields.parse_dictionary(field)
    parsed.must_equal value
    Rack::StructuredFields.serialize_dictionary(parsed).must_equal field
  end

  it 'serializes empty lists and dictionaries canonically' do
    Rack::StructuredFields.serialize_list([]).must_equal ''
    Rack::StructuredFields.serialize_dictionary({}).must_equal ''
    Rack::StructuredFields.parse_list('').must_equal []
    Rack::StructuredFields.parse_dictionary('').must_equal Hash.new
  end

  it 'serializes inner lists without an extra leading space' do
    Rack::StructuredFields.serialize_list([
      InnerList.new([1, 2])
    ]).must_equal '(1 2)'
  end

  it 'serializes parameterized and bare values' do
    Rack::StructuredFields.serialize_item(5).must_equal '5'
    Rack::StructuredFields.serialize_item(Item.new(5, { "a" => true })).must_equal '5;a'
    Rack::StructuredFields.serialize_list([InnerList.new([Item.new(1, { "x" => 2 })], { "y" => "z" })]).
      must_equal '(1;x=2);y="z"'
  end

  it 'reports the byte position of out-of-range decimals' do
    error = assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('1.1234')
    end
    error.position.must_equal 5
    error.message.must_include 'byte position 5'

    error = assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('9999999999999.0')
    end
    error.position.must_equal 0
  end

  it 'rejects repeated dictionary and parameter keys' do
    error = assert_raises(ParseError) do
      Rack::StructuredFields.parse_dictionary('a=1, a=2')
    end
    error.position.must_equal 5

    assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('1;a=1;a=2')
    end

    assert_raises(StructuredFieldError) do
      Rack::StructuredFields.serialize_dictionary([["a", 1], ["a", 2]])
    end
  end

  it 'rejects invalid Unicode without repairing it' do
    invalid_string = "\"\xFF\"" .b
    assert_raises(ParseError) do
      Rack::StructuredFields.parse_item(invalid_string)
    end

    invalid_display = '%"%FF"%'.b
    error = assert_raises(ParseError) do
      Rack::StructuredFields.parse_item(invalid_display)
    end
    error.position.must_equal 2

    assert_raises(StructuredFieldError) do
      Rack::StructuredFields.serialize_item(String.new("\xFF".b, encoding: Encoding::UTF_8))
    end
  end

  it 'rejects invalid structure and serialization values' do
    [
      '1,',
      '(1,)',
      '-.',
      '?2',
      '@x',
      ':a!b:',
      '"unterminated',
      '%"unterminated',
      '1;a=1;a=2'
    ].each do |field|
      assert_raises(ParseError) do
        Rack::StructuredFields.parse_list(field)
      end
    end

    [
      1_000_000_000_000_000,
      -1_000_000_000_000_000,
      Decimal.new("9999999999999.0"),
      Decimal.new("1.1234"),
      Float::NAN,
      Rational(1, 2)
    ].each do |value|
      assert_raises(StructuredFieldError) do
        Rack::StructuredFields.serialize_item(value)
      end
    end
  end

  it 'compares exact decimals numerically with other numeric values' do
    Decimal.new("1.50").must_equal 1.5
    Decimal.new("1.50").must_equal Rational(15, 10)
    Decimal.new("1.50").to_f.must_equal 1.5
    Decimal.new("-0.50").to_s.must_equal "-0.5"
  end

  it 'places dictionary item parameters after the value' do
    field = 'u=u;v=v'
    value = { "u" => Item.new(Token.new("u"), { "v" => Token.new("v") }) }
    Rack::StructuredFields.parse_dictionary(field).must_equal value
    Rack::StructuredFields.serialize_dictionary(value).must_equal field
  end

  it 'uses an equals sign for plain array dictionary values' do
    Rack::StructuredFields.serialize_dictionary("a" => [1, 2]).must_equal 'a=(1 2)'
  end

  it 'supports decode and encode aliases' do
    Rack::StructuredFields.decode_list('1, 2').must_equal [Item.new(1), Item.new(2)]
    Rack::StructuredFields.encode_list([1, 2]).must_equal '1, 2'
  end

  it 'preserves byte sequence values and display string percent decoding' do
    parsed = Rack::StructuredFields.parse_item(':aGVsbG8=:; label=%"caf%C3%A9%22%25"%')
    parsed.value.value.must_equal "hello".b
    parsed.parameters["label"].must_equal DisplayString.new("caf\xC3\xA9\"%")

    Rack::StructuredFields.serialize_item(parsed).must_equal ':aGVsbG8=:;label=%"caf%C3%A9%22%25"%'
  end

  it 'accepts lowercase percent escapes and serializes them as uppercase' do
    parsed = Rack::StructuredFields.parse_item('%"%c3%a9%00"%')
    parsed.value.must_equal DisplayString.new("\xC3\xA9\x00".b.force_encoding(Encoding::UTF_8))
    Rack::StructuredFields.serialize_item(parsed).must_equal '%"%C3%A9%00"%'

    assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('%"%ff"%')
    end

    assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('%"%ed%a0%80"%')
    end
    assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('%"%f4%90%80%80"%')
    end
  end

  it 'rejects decimal scale overflow from the fourth fractional byte' do
    error = assert_raises(ParseError) do
      Rack::StructuredFields.parse_item('-0.0001')
    end
    error.position.must_equal 6
  end

  it 'rejects duplicated parameters across a dictionary key and value' do
    error = assert_raises(ParseError) do
      Rack::StructuredFields.parse_dictionary('a;a=1=(1);a=2')
    end
    error.position.must_equal 0
  end
end
