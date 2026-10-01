# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/message_signatures'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/lint'
end

require 'openssl'

describe Rack::MessageSignatures do
  # Test fixtures: the middleware never sees these until injected through
  # the +keys+ option.
  FIXTURE_KEYS = {
    'partner-key-a' => 'fixture-secret-alpha-0001',
    'partner-key-b' => 'fixture-secret-beta-0002',
  }.freeze

  # Independent RFC 9421 signer used to produce request signatures.
  # +components+ are serialized component identifiers, e.g. "@method",
  # "@query-param";name="tag" or "content-type".
  def sign(label:, key:, keyid:, components:, created: nil, expires: nil, alg: '"hmac-sha256"',
           method: 'GET', authority: 'example.org', path: '/', query: '', headers: {})
    lines = components.map do |component|
      "#{component}: #{component_value(component, method, authority, path, query, headers)}"
    end
    params = +""
    params << ";created=#{created}" if created
    params << ";expires=#{expires}" if expires
    params << %(;keyid="#{keyid}")
    params << ";alg=#{alg}" if alg
    signature_params = "(#{components.join(' ')})#{params}"
    lines << %("@signature-params": #{signature_params})
    signature = [OpenSSL::HMAC.digest('sha256', key, lines.join("\n"))].pack('m0')
    { input: "#{label}=#{signature_params}", signature: "#{label}=:#{signature}:" }
  end

  def component_value(component, method, authority, path, query, headers)
    case component
    when '"@method"' then method
    when '"@authority"' then authority
    when '"@path"' then path.empty? ? '/' : path
    when '"@query"' then "?#{query}"
    when /\A"@query-param"/
      signer_query_param(query, component[/name="([^"]*)"/, 1])
    else
      headers.fetch(component.delete('"').downcase) { raise "signer missing header #{component}" }
    end
  end

  def signer_query_param(query, name)
    values = []
    query.to_s.split('&', -1).each do |pair|
      pair_name, _, pair_value = pair.partition('=')
      values << Rack::Utils.unescape(pair_value) if Rack::Utils.unescape(pair_name) == name
    end
    raise "signer: ambiguous query parameter #{name}" unless values.length == 1
    values.first
  end

  def signature_headers(*signed)
    {
      'HTTP_SIGNATURE_INPUT' => signed.map { |s| s[:input] }.join(', '),
      'HTTP_SIGNATURE' => signed.map { |s| s[:signature] }.join(', '),
    }
  end

  def build_app(lint: true, **options)
    @app_calls = 0
    inner = lambda { |env|
      @app_calls += 1
      [200, { 'content-type' => 'text/plain' }, ['OK']]
    }
    middleware = Rack::MessageSignatures.new(inner, keys: FIXTURE_KEYS, **options)
    lint ? Rack::Lint.new(middleware) : middleware
  end

  def app_called?
    @app_calls > 0
  end

  def default_app(**options)
    build_app(required_components: %w[@method @authority],
              allowed_keyids: %w[partner-key-a partner-key-b], **options)
  end

  def valid_signature(**overrides)
    sign(**{ label: 'sig1', key: FIXTURE_KEYS['partner-key-a'], keyid: 'partner-key-a',
             components: ['"@method"', '"@authority"'], created: Time.now.to_i }.merge(overrides))
  end

  it 'accepts a valid signature covering the required components' do
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(valid_signature))
    response.status.must_equal 200
    response.body.must_equal 'OK'
    assert app_called?
  end

  it 'rejects requests without any signature headers' do
    response = Rack::MockRequest.new(default_app).get('https://example.org/')
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects malformed Signature-Input fields' do
    response = Rack::MockRequest.new(default_app).get('https://example.org/',
      'HTTP_SIGNATURE_INPUT' => 'sig1=("@method"',
      'HTTP_SIGNATURE' => 'sig1=:AAAA:')
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects a signature made with the wrong secret' do
    response = Rack::MockRequest.new(default_app).get('https://example.org/',
      signature_headers(valid_signature(key: 'not-the-secret')))
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects keyids outside the allowed list' do
    signed = valid_signature(key: FIXTURE_KEYS['partner-key-b'], keyid: 'partner-key-b')
    response = Rack::MockRequest.new(default_app(allowed_keyids: %w[partner-key-a])).get(
      'https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects unknown keyids' do
    signed = valid_signature(key: 'whatever', keyid: 'unknown-key')
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'supports a callable for key lookup' do
    middleware = build_app(required_components: %w[@method @authority],
                           keys: ->(keyid) { FIXTURE_KEYS[keyid] })
    response = Rack::MockRequest.new(middleware).get('https://example.org/', signature_headers(valid_signature))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects when a required component is not covered' do
    signed = valid_signature(components: ['"@method"'])
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects a valid signature whose components are reordered' do
    # The signature itself verifies, but the server requires @method to be
    # covered before @authority.
    signed = valid_signature(components: ['"@authority"', '"@method"'])
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'accepts signatures covering more than the required components' do
    signed = valid_signature(components: ['"@method"', '"@authority"', '"@path"', '"@query"'], path: '/callback')
    response = Rack::MockRequest.new(default_app).get('https://example.org/callback', signature_headers(signed))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects when the path is tampered with after signing' do
    signed = valid_signature(components: ['"@method"', '"@authority"', '"@path"'], path: '/callback')
    response = Rack::MockRequest.new(default_app).get('https://example.org/forged', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'verifies @query and rejects query tampering' do
    components = ['"@method"', '"@authority"', '"@query"']
    signed = valid_signature(components: components, query: 'a=1&b=2')
    middleware = default_app
    ok = Rack::MockRequest.new(middleware).get('https://example.org/?a=1&b=2', signature_headers(signed))
    ok.status.must_equal 200

    forged = Rack::MockRequest.new(middleware).get('https://example.org/?a=1&b=3', signature_headers(signed))
    forged.status.must_equal 401
  end

  it 'verifies @query-param including empty values' do
    components = ['"@method"', '"@authority"', '"@query-param";name="tag"', '"@query-param";name="flag"']
    signed = valid_signature(components: components, query: 'tag=hello&flag=')
    response = Rack::MockRequest.new(default_app).get('https://example.org/?tag=hello&flag=', signature_headers(signed))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects @query-param when the parameter is repeated' do
    # Signed over a single value; the request repeats the parameter, which
    # RFC 9421 2.2.9 makes invalid.
    components = ['"@method"', '"@authority"', '"@query-param";name="tag"']
    signed = valid_signature(components: components, query: 'tag=a')
    response = Rack::MockRequest.new(default_app).get('https://example.org/?tag=a&tag=b', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects @query-param when the parameter is absent' do
    components = ['"@method"', '"@authority"', '"@query-param";name="tag"']
    signed = valid_signature(components: components, query: 'tag=a')
    response = Rack::MockRequest.new(default_app).get('https://example.org/?other=1', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'verifies signed header fields' do
    components = ['"@method"', '"@authority"', '"content-type"', '"x-partner-id"']
    signed = valid_signature(components: components, method: 'POST',
                             headers: { 'content-type' => 'application/json', 'x-partner-id' => 'abc123' })
    response = Rack::MockRequest.new(default_app).post('https://example.org/callback',
      'CONTENT_TYPE' => 'application/json', 'HTTP_X_PARTNER_ID' => 'abc123',
      :input => '{}', **signature_headers(signed))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects when a signed header field is missing from the request' do
    components = ['"@method"', '"@authority"', '"x-partner-id"']
    signed = valid_signature(components: components, headers: { 'x-partner-id' => 'abc123' })
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'verifies empty header field values' do
    components = ['"@method"', '"@authority"', '"x-empty"']
    signed = valid_signature(components: components, headers: { 'x-empty' => '' })
    response = Rack::MockRequest.new(default_app).get('https://example.org/',
      signature_headers(signed).merge('HTTP_X_EMPTY' => ''))
    response.status.must_equal 200
    assert app_called?
  end

  it 'combines repeated field lines with ", " per RFC 9421 2.1' do
    components = ['"@method"', '"@authority"', '"x-multi"']
    signed = valid_signature(components: components, headers: { 'x-multi' => 'a, b' })
    middleware = build_app(lint: false, required_components: %w[@method @authority])
    env = Rack::MockRequest.env_for('https://example.org/', 'HTTP_X_MULTI' => "a\nb")
    status, = middleware.call(env.merge(signature_headers(signed)))
    status.must_equal 200
    assert app_called?
  end

  it 'accepts a request when one of several signatures is fully valid' do
    good = valid_signature(label: 'sig2')
    bad = valid_signature(label: 'sig1', key: 'wrong-secret')
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(bad, good))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects when no single signature covers all required components' do
    # Two individually valid signatures whose coverage would only satisfy
    # the policy if combined; coverage must not be pieced together.
    only_method = valid_signature(label: 'sig1', components: ['"@method"'])
    only_authority = valid_signature(label: 'sig2', components: ['"@authority"'])
    response = Rack::MockRequest.new(default_app).get('https://example.org/',
      signature_headers(only_method, only_authority))
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects when a Signature-Input label has no matching Signature' do
    signed = valid_signature
    response = Rack::MockRequest.new(default_app).get('https://example.org/',
      'HTTP_SIGNATURE_INPUT' => signed[:input],
      'HTTP_SIGNATURE' => 'other=:AAAA:')
    response.status.must_equal 401
    refute app_called?
  end

  it 'rejects unsupported signature algorithms' do
    signed = valid_signature(alg: '"rsa-v1_5-sha256"')
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'accepts a signature without an alg parameter' do
    signed = valid_signature(alg: nil)
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects expired signatures' do
    signed = valid_signature(expires: Time.now.to_i - 10)
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'accepts signatures that expire in the future' do
    signed = valid_signature(expires: Time.now.to_i + 60)
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 200
    assert app_called?
  end

  it 'rejects signatures created too far in the future' do
    signed = valid_signature(created: Time.now.to_i + 3600)
    response = Rack::MockRequest.new(default_app).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end

  it 'enforces the configured validity window' do
    middleware = default_app(max_age: 300)

    fresh = valid_signature(created: Time.now.to_i - 60)
    ok = Rack::MockRequest.new(middleware).get('https://example.org/', signature_headers(fresh))
    ok.status.must_equal 200

    stale = valid_signature(created: Time.now.to_i - 600)
    rejected = Rack::MockRequest.new(middleware).get('https://example.org/', signature_headers(stale))
    rejected.status.must_equal 401
  end

  it 'requires created when a validity window is configured' do
    signed = valid_signature(created: nil)
    response = Rack::MockRequest.new(default_app(max_age: 300)).get('https://example.org/', signature_headers(signed))
    response.status.must_equal 401
    refute app_called?
  end
end
