# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/auth/signature'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/lint'
end

describe Rack::Auth::Signature do
  KEY = 'partner-secret'
  REQUIRED_COMPONENTS = ['@method', '@authority', '@path',
                         { component: '@query-param', parameters: { name: 'p' } },
                         'x-date', 'content-type', 'x-custom']

  def signed_app(required_components: REQUIRED_COMPONENTS, allowed_keyids: %w[partner],
                max_age: 300, clock_skew: 0, require_created: false,
                clock: -> { Time.at(100) }, keys: { 'partner' => KEY })
    app = lambda do |env|
      [200, { 'content-type' => 'text/plain' }, ['accepted']]
    end

    Rack::Lint.new(Rack::Auth::Signature.new(
      app,
      required_components: required_components,
      allowed_keyids: allowed_keyids,
      max_age: max_age,
      clock_skew: clock_skew,
      require_created: require_created,
      clock: clock
    ) { |keyid| keys[keyid] })
  end

  def signed_request(path: '/callbacks?x=one&empty=&p=%C3%A9&p2=b', method: 'GET',
                     components: default_components, input_components: nil,
                     keyid: 'partner', alg: 'hmac-sha256', created: 100, expires: nil,
                     secret: KEY, label: 'sig', headers: {}, app_options: {},
                     signature_input: nil, signature: nil, field_values: {})
    app = signed_app(**app_options)
    input_components ||= components
    signature_input ||= signature_input_for(label, input_components, keyid: keyid, alg: alg,
                                            created: created, expires: expires)
    if signature.nil?
      base = signature_base_for(path, components, signature_input, label, field_values)
      signature = encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), secret, base))
    end

    request_headers = {
      'HTTP_HOST' => 'example.org',
      'HTTP_X_DATE' => 'Sun, 30 Sep 2026 00:01:40 GMT',
      'CONTENT_TYPE' => 'application/json; charset=utf-8',
      'HTTP_X_CUSTOM' => " first value \t"
    }.merge(headers)
    request_headers['HTTP_SIGNATURE'] = "#{label}=:#{signature}:"
    request_headers['HTTP_SIGNATURE_INPUT'] = signature_input
    request_headers.merge!(app_options)

    Rack::MockRequest.new(app).request(method, path, request_headers)
  end

  def default_components
    [
      '@method',
      '@authority',
      '@path',
      { component: '@query-param', parameters: { name: 'p' } },
      'x-date',
      'content-type',
      'x-custom'
    ]
  end

  def component_value(component, path, field_values = {})
    uri = URI.parse(path)
    case component
    when '@method' then sf_escape('GET')
    when '@authority' then sf_escape('example.org')
    when '@path' then sf_escape(uri.path)
    when '@query' then sf_escape(uri.query.to_s)
    when String then sf_escape(field_values.fetch(component) { HTTP_FIELD_VALUES.fetch(component) })
    when Hash
      name = component[:parameters][:name]
      value = field_values.fetch('@query-param', p_encode_query(query_pairs(uri.query.to_s).fetch(name)))
      sf_escape(value)
    end
  end

  def query_pairs(query)
    query.split('&', -1).each_with_object({}) do |pair, values|
      name, value = pair.split('=', 2)
      decoded_name = URI.decode_www_form_component(name || '', Encoding::BINARY)
      values[decoded_name] = URI.decode_www_form_component(value || '', Encoding::BINARY)
    end
  end

  def p_encode_query(value)
    URI.encode_www_form_component(value).gsub('+', '%20')
  end

  def identifier_for(component)
    case component
    when Hash
      name = component[:component]
      parameters = component[:parameters].map do |key, value|
        ";#{key}=\"#{value}\""
      end.join
      "\"#{name}\"#{parameters}"
    else
      "\"#{component}\""
    end
  end

  def signature_base_for(path, components, signature_input, label, field_values = {})
    lines = components.map do |component|
      "#{identifier_for(component)}: #{component_value(component, path, field_values)}"
    end
    inner_list = signature_input[/\A#{Regexp.escape(label)}=\((.*)\);keyid=/m, 1]
    params = signature_input[/;keyid=.*\z/]
    lines << "\"@signature-params\": (#{inner_list})#{params}"
    lines.join("\n")
  end

  def signature_input_for(label, components, keyid:, alg:, created:, expires:)
    list = components.map { |component| identifier_for(component) }.join(' ')
    params = ";keyid=\"#{keyid}\";alg=\"#{alg}\"".dup
    params << ";created=#{created}" unless created.nil?
    params << ";expires=#{expires}" unless expires.nil?
    "#{label}=(#{list})#{params}"
  end

  def sf_escape(value)
    "\"#{value.gsub(/([\\\"])/) { "\\#{$1}" }}\""
  end

  def encode64(value)
    [value].pack('m0')
  end

  HTTP_FIELD_VALUES = {
    'x-date' => 'Sun, 30 Sep 2026 00:01:40 GMT',
    'content-type' => 'application/json; charset=utf-8',
    'x-custom' => 'first value'
  }.freeze

  it 'accepts a valid HMAC-SHA256 signature over ordinary fields and all special components' do
    response = signed_request
    response.status.must_equal 200
    response.body.must_equal 'accepted'
  end

  it 'accepts a complete signature using @query instead of individual query parameters' do
    components = ['@method', '@authority', '@path', '@query', 'x-date', 'content-type', 'x-custom']
    response = signed_request(
      components: components,
      input_components: components,
      app_options: { required_components: components }
    )
    response.status.must_equal 200
  end

  it 'canonicalizes empty and decoded query parameters' do
    response = signed_request(path: '/callbacks?empty=&p=%20')
    response.status.must_equal 200
  end

  it 'accepts an empty @query-param value' do
    components = ['@method', '@authority', '@path',
                  { component: '@query-param', parameters: { name: 'empty' } }]
    response = signed_request(
      components: components,
      input_components: components,
      app_options: { required_components: components, max_age: nil }
    )
    response.status.must_equal 200
  end

  it 'rejects malformed query percent escapes in signed parameters' do
    components = [{ component: '@query-param', parameters: { name: 'p' } }]
    input = signature_input_for('sig', components, keyid: 'partner', alg: 'hmac-sha256',
                                created: nil, expires: nil)
    env = Rack::MockRequest.env_for('/callbacks',
                                    'HTTP_SIGNATURE' => "sig=:#{encode64("\0" * 32)}:",
                                    'HTTP_SIGNATURE_INPUT' => input)
    env['QUERY_STRING'] = 'p=%zz'
    response = Rack::MockResponse.new(*Rack::Lint.new(Rack::Auth::Signature.new(
      ->(_) { [200, { 'content-type' => 'text/plain' }, ['ok']] },
      required_components: components,
      allowed_keyids: %w[partner]
    ) { KEY }).call(env))
    response.status.must_equal 401
  end

  it 'rejects repeated query parameters for a signed @query-param name' do
    response = signed_request(
      path: '/callbacks?x=one&empty=&p=%C3%A9&p=%C3%A8&p2=b',
      signature_input: signature_input_for('sig', default_components, keyid: 'partner',
                                          alg: 'hmac-sha256', created: 100, expires: nil),
      field_values: { '@query-param' => '%C3%A9' }
    )
    response.status.must_equal 401
    response.body.must_be :empty?
  end

  it 'rejects combining @query and @query-param in one signature' do
    components = ['@query', { component: '@query-param', parameters: { name: 'x' } }]
    response = signed_request(
      app_options: { required_components: components },
      components: components,
      input_components: components,
      path: '/callbacks?x=1'
    )
    response.status.must_equal 401
  end

  it 'verifies each signature independently and accepts one complete valid signature' do
    bad_input = signature_input_for('bad', ['@method'], keyid: 'partner', alg: 'hmac-sha256',
                                    created: 100, expires: nil)
    bad_base = [
      '@method: "GET"',
      bad_input.sub('bad=', '')
    ].join("\n")
    bad_signature = encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), KEY, bad_base))
    good_input = signature_input_for('good', default_components, keyid: 'partner', alg: 'hmac-sha256',
                                     created: 100, expires: nil)
    good_base = signature_base_for('/callbacks?x=one&empty=&p=%C3%A9&p2=b', default_components, good_input, 'good')
    good_signature = encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), KEY, good_base))
    env = Rack::MockRequest.env_for(
      '/callbacks?x=one&empty=&p=%C3%A9&p2=b',
      'HTTP_HOST' => 'example.org',
      'HTTP_SIGNATURE' => "bad=:#{bad_signature}:, good=:#{good_signature}:",
      'HTTP_SIGNATURE_INPUT' => "#{bad_input}, #{good_input}",
      'HTTP_X_DATE' => HTTP_FIELD_VALUES['x-date'],
      'CONTENT_TYPE' => 'application/json; charset=utf-8',
      'HTTP_X_CUSTOM' => " first value \t"
    )
    response = Rack::MockResponse.new(*signed_app.call(env))
    response.status.must_equal 200
  end

  it 'does not combine partial coverage from multiple signatures' do
    method_components = ['@method', '@authority', '@path',
                         { component: '@query-param', parameters: { name: 'p' } }, 'x-date']
    header_components = ['content-type', 'x-custom']
    path = '/callbacks?x=one&empty=&p=%C3%A9&p2=b'
    method_input = signature_input_for('method', method_components, keyid: 'partner', alg: 'hmac-sha256',
                                       created: 100, expires: nil)
    header_input = signature_input_for('headers', header_components, keyid: 'partner', alg: 'hmac-sha256',
                                       created: 100, expires: nil)
    method_base = signature_base_for(path, method_components, method_input, 'method')
    header_base = signature_base_for(path, header_components, header_input, 'headers')
    env = Rack::MockRequest.env_for(
      path,
      'HTTP_HOST' => 'example.org',
      'HTTP_SIGNATURE' => "method=:#{encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), KEY, method_base))}:, " \
        "headers=:#{encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), KEY, header_base))}:",
      'HTTP_SIGNATURE_INPUT' => "#{method_input}, #{header_input}",
      'HTTP_X_DATE' => HTTP_FIELD_VALUES['x-date'],
      'CONTENT_TYPE' => 'application/json; charset=utf-8',
      'HTTP_X_CUSTOM' => " first value \t"
    )
    response = Rack::MockResponse.new(*signed_app.call(env))
    response.status.must_equal 401
  end

  it 'rejects a valid signature when required components were reordered' do
    reordered = default_components.rotate(1)
    response = signed_request(components: reordered, input_components: reordered)
    response.status.must_equal 401
  end

  it 'rejects a valid signature when a required component is omitted' do
    omitted = default_components - ['x-custom']
    response = signed_request(components: omitted, input_components: omitted,
                               headers: { 'HTTP_X_CUSTOM' => 'changed' })
    response.status.must_equal 401
  end

  it 'rejects expired signatures' do
    response = signed_request(created: 1, expires: 90)
    response.status.must_equal 401
  end

  it 'rejects future signatures beyond configured clock skew' do
    response = signed_request(created: 102, app_options: { clock_skew: 0 })
    response.status.must_equal 401
  end

  it 'accepts future signatures within configured clock skew' do
    response = signed_request(created: 101, app_options: { clock_skew: 1 })
    response.status.must_equal 200
  end

  it 'rejects disallowed keyids' do
    response = signed_request(keyid: 'other', secret: KEY)
    response.status.must_equal 401
  end

  it 'rejects invalid HMAC secrets' do
    response = signed_request(secret: 'wrong-secret')
    response.status.must_equal 401
  end

  it 'rejects malformed structured fields without calling the application' do
    response = signed_request(signature_input: 'sig=("@method")keyid="partner"')
    response.status.must_equal 401
    response.body.must_be :empty?
  end

  it 'requires keyid, alg, and created when configured' do
    %w[keyid alg created].each do |missing|
      components = default_components
      input = signature_input_for('sig', components, keyid: 'partner', alg: 'hmac-sha256',
                                  created: 100, expires: nil).sub(/;#{missing}=[^;]+/, '')
      response = signed_request(
        signature_input: input,
        signature: encode64("\0" * 32),
        app_options: { require_created: true }
      )
      response.status.must_equal 401
    end
  end

  it 'rejects unknown special components and empty ordinary fields' do
    components = ['@unknown']
    input = signature_input_for('sig', components, keyid: 'partner', alg: 'hmac-sha256',
                                created: nil, expires: nil)
    base = '"@unknown": ""\n' + input.sub('sig=', '')
    response = signed_request(
      components: components,
      input_components: components,
      app_options: { required_components: components, max_age: nil },
      signature: encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), KEY, base))
    )
    response.status.must_equal 401

    response = signed_request(headers: { 'HTTP_X_CUSTOM' => '   ' })
    response.status.must_equal 401
  end

  it 'canonicalizes repeated ordinary field values and rejects changed field content' do
    components = ['x-custom']
    input = signature_input_for('sig', components, keyid: 'partner', alg: 'hmac-sha256',
                                created: 100, expires: nil)
    base = signature_base_for('/callbacks', components, input, 'sig',
                              'x-custom' => 'one, two')
    signature = encode64(OpenSSL::HMAC.digest(OpenSSL::Digest.new('SHA256'), KEY, base))
    app = Rack::Auth::Signature.new(
      ->(_env) { [200, { 'content-type' => 'text/plain' }, ['ok']] },
      required_components: components,
      allowed_keyids: %w[partner],
      require_created: true
    ) { KEY }
    env = Rack::MockRequest.env_for(
      '/callbacks',
      'HTTP_SIGNATURE' => "sig=:#{signature}:",
      'HTTP_SIGNATURE_INPUT' => input,
      'HTTP_X_CUSTOM' => ['one', 'two']
    )
    Rack::MockResponse.new(*app.call(env)).status.must_equal 200

    env['HTTP_X_CUSTOM'] = ['one', 'changed']
    Rack::MockResponse.new(*app.call(env)).status.must_equal 401
  end
end
