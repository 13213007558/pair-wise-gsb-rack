# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/structured_fields'
end

describe Rack::StructuredFields do
  SF = Rack::StructuredFields

  def parse(shape, value)
    SF.parse(shape, value)
  end

  def serialize(shape, value)
    SF.serialize(shape, value)
  end

  it "parses and serializes all item bare value types" do
    item = SF::Item.new(
      SF::Token.new("text/plain"),
      {
        "n" => -42,
        "d" => 1.5,
        "b" => false,
        "bin" => SF::ByteSequence.new("abc"),
        "date" => SF::Date.new(1659578233),
        "label" => SF::DisplayString.new("café")
      }
    )

    wire = 'text/plain ; n=-42 ; d=1.5 ; b=?0 ; bin=:YWJj: ; ' \
           'date=@1659578233 ; label=%"caf%C3%A9"'

    parsed = parse(:item, wire)
    parsed.must_equal item
    serialize(:item, parsed).must_equal wire
  end

  it "preserves quoted strings that contain commas and escapes" do
    wire = '",\"\\\"'
    item = SF::Item.new(",\"\\", {})

    parse(:item, wire).must_equal item
    serialize(:item, item).must_equal wire
  end

  it "preserves parameterized inner lists and list structure" do
    wire = '(1 ; a="x," 2.25 ; b=?0) ; v="p1", ("x" "y")'
    expected = [
      SF::InnerList.new(
        [
          SF::Item.new(1, { "a" => "x," }),
          SF::Item.new(2.25, { "b" => false })
        ],
        { "v" => "p1" }
      ),
      SF::InnerList.new([SF::Item.new("x"), SF::Item.new("y")])
    ]

    parsed = parse(:list, wire)
    parsed.must_equal expected
    serialize(:list, parsed).must_equal wire
  end

  it "preserves dictionary members and parameter order" do
    wire = 'u=1 ; p=2, t, v=(1 2) ; q=:AA==:, bin=:YWJj:, when=@-1659578233, ' \
           'name=%"%E4%BD%A0%E5%A5%BD"'
    expected = {
      "u" => SF::Item.new(1, { "p" => 2 }),
      "t" => true,
      "v" => SF::InnerList.new(
        [SF::Item.new(1), SF::Item.new(2)],
        { "q" => SF::ByteSequence.new("\x00") }
      ),
      "bin" => SF::ByteSequence.new("abc"),
      "when" => SF::Date.new(-1659578233),
      "name" => SF::DisplayString.new("你好")
    }

    parsed = parse(:dictionary, wire)
    parsed.must_equal expected
    serialize(:dictionary, parsed).must_equal wire
  end

  it "returns empty lists and dictionaries" do
    parse(:list, "").must_equal []
    parse(:list, " \t ").must_equal []
    parse(:dictionary, "").must_equal({})
  end

  it "canonicalizes legal but non-canonical numeric whitespace" do
    parsed = parse(:list, " 01.50 ,\t-2.0 ")
    parsed.must_equal [SF::Item.new(1.5), SF::Item.new(-2.0)]
    serialize(:list, parsed).must_equal "1.5, -2.0"
  end

  it "rejects out-of-range decimals" do
    error = assert_raises(SF::ParseError) do
      parse(:item, "1000000000000.0")
    end
    error.byte_position.must_equal 0
    error.message.must_include "at byte 0"

    error = assert_raises(SF::ParseError) do
      parse(:item, "1.2345")
    end
    error.byte_position.must_equal 5

    assert_raises(SF::SerializationError) do
      serialize(:item, SF::Item.new(0.0001))
    end
  end

  it "rejects duplicate dictionary keys and parameter keys" do
    error = assert_raises(SF::ParseError) do
      parse(:dictionary, "a=1, a=2")
    end
    error.byte_position.must_equal 5

    error = assert_raises(SF::ParseError) do
      parse(:item, '1 ; a=1 ; a=2')
    end
    error.byte_position.must_equal 10
  end

  it "reports raw byte positions for parsing failures" do
    vectors = [
      [:item, "ab,", "unexpected trailing bytes", 2],
      [:item, %q{"\u007F"}, "invalid string escape", 1],
      [:item, ":aa=:", "invalid base64 padding", 3],
      [:item, %q{"café"}, "invalid string character", 4],
      [:item, "%\"%ED%A0%80\"", "overlong or out-of-range UTF-8 sequence", 2],
      [:item, "@1.0", "unexpected trailing bytes", 2],
      [:item, "?2", "expected boolean", 1],
      [:list, "(1 2", "unterminated inner list", 4],
      [:list, "1,,2", "expected bare item", 2]
    ]

    vectors.each do |shape, input, message, position|
      error = assert_raises(SF::ParseError, "#{shape}: #{input.inspect}") do
        parse(shape, input.b)
      end
      error.message.must_include message
      error.byte_position.must_equal position
    end
  end

  it "validates Unicode in display strings" do
    assert_raises(SF::ParseError) do
      parse(:item, "%\"%ED%A0%80\"")
    end

    assert_raises(SF::ParseError) do
      parse(:item, "%\"%E2%28%A1\"")
    end
  end

  it "does not silently repair invalid serialization input" do
    [
      SF::Token.new("1abc"),
      SF::Item.new("café"),
      SF::Item.new(1_000_000_000_000_000),
      SF::Item.new(Float::NAN),
      SF::Item.new(0.0001),
      SF::Item.new(:token)
    ].each do |item|
      assert_raises(SF::SerializationError) do
        serialize(:item, item)
      end
    end

    invalid_binary = "\xff".b
    assert_raises(SF::SerializationError) do
      serialize(:item, SF::Item.new(invalid_binary))
    end

    assert_raises(SF::SerializationError) do
      serialize(:dictionary, { "BAD" => true })
    end

    assert_raises(SF::SerializationError) do
      serialize(:list, [1])
    end
  end
end
