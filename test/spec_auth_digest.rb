# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/auth/digest'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/lint'
end

require 'digest'

describe Rack::Auth::Digest::Params do
  it 'parses quoted values containing commas and escaped quotes' do
    params = Rack::Auth::Digest::Params.parse('a="x, \\"y\\"", b=token, c=')
    params['a'].must_equal 'x, "y"'
    params['b'].must_equal 'token'
    params['c'].must_equal ''
  end

  it 'round-trips quoted values' do
    params = Rack::Auth::Digest::Params
    value = 'weird, "quoted" \\ value'
    params.parse("k=#{params.quote(value)}")['k'].must_equal value
  end
end

describe Rack::Auth::Digest do
  def realm
    'digest-realm'
  end

  def user_password
    's3cret'
  end

  def sha256(string)
    ::Digest::SHA256.hexdigest(string)
  end

  def ha1(username)
    sha256("#{username}:#{realm}:#{user_password}")
  end

  before do
    @now = Time.at(1_800_000_000)
    @users = {}
    @nonce_store = Rack::Auth::Digest::MemoryNonceStore.new(clock: -> { @now })
  end

  def unprotected_app
    Rack::Lint.new lambda { |env|
      body = env['rack.input'] ? env['rack.input'].read : ''
      [200, { 'content-type' => 'text/plain' }, ["Hi #{env['REMOTE_USER']}:#{body}"]]
    }
  end

  def protected_app(algorithm: 'SHA-256', qops: %w[auth auth-int])
    nonce_store = @nonce_store
    Rack::Auth::Digest.new(unprotected_app,
      realm: realm, algorithm: algorithm, qops: qops,
      nonce_ttl: 60, opaque: 'test-opaque',
      clock: -> { @now }, nonce_store: nonce_store) do |username|
      @users[username]
    end
  end

  def challenge_for(app, method: 'GET', uri: '/', input: nil)
    options = {}
    options[:input] = input if input
    response = Rack::MockRequest.new(app).request(method, uri, options)
    response.status.must_equal 401
    header = response.headers['www-authenticate']
    header.must_match(/\ADigest /)
    Rack::Auth::Digest::Params.parse(header.sub(/\ADigest\s+/, ''))
  end

  def authorization(challenge, username:, password: user_password, algorithm: 'SHA-256',
                    qop: 'auth', method: 'GET', uri: '/', body: '',
                    nc: '00000001', cnonce: 'client-nonce', nonce: nil)
    nonce ||= challenge['nonce']
    user_digest = sha256("#{username}:#{realm}:#{password}")
    user_digest = sha256("#{user_digest}:#{nonce}:#{cnonce}") if algorithm == 'SHA-256-sess'
    ha2 = if qop == 'auth-int'
            sha256("#{method}:#{uri}:#{sha256(body)}")
          else
            sha256("#{method}:#{uri}")
          end
    response = sha256("#{user_digest}:#{nonce}:#{nc}:#{cnonce}:#{qop}:#{ha2}")
    params = Rack::Auth::Digest::Params
    'Digest ' + [
      "username=#{params.quote(username)}",
      "realm=#{params.quote(realm)}",
      "nonce=#{params.quote(nonce)}",
      "uri=#{params.quote(uri)}",
      "response=#{params.quote(response)}",
      "algorithm=#{algorithm}",
      "qop=#{qop}",
      "nc=#{nc}",
      "cnonce=#{params.quote(cnonce)}",
      "opaque=#{params.quote(challenge['opaque'])}"
    ].join(', ')
  end

  def digest_get(app, header, uri: '/')
    Rack::MockRequest.new(app).get(uri, 'HTTP_AUTHORIZATION' => header)
  end

  def digest_post(app, header, body, uri: '/')
    Rack::MockRequest.new(app).post(uri,
      'CONTENT_TYPE' => 'text/plain', :input => body, 'HTTP_AUTHORIZATION' => header)
  end

  it 'challenges with RFC 7616 parameters when no credentials are specified' do
    response = Rack::MockRequest.new(protected_app).get('/')
    response.status.must_equal 401
    header = response.headers['www-authenticate']
    header.must_match(/Digest realm="digest-realm"/)
    header.must_include 'qop="auth,auth-int"'
    header.must_include 'algorithm=SHA-256'
    header.must_include 'opaque="test-opaque"'
    header.must_match(/nonce="[0-9a-f]{32}"/)
    header.wont_include 'stale'
    response.body.must_be :empty?
  end

  it 'completes a full SHA-256 qop=auth handshake' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    response = digest_get(app, authorization(challenge, username: 'alice'))
    response.status.must_equal 200
    response.body.must_equal 'Hi alice:'
  end

  it 'completes a full SHA-256-sess handshake' do
    @users['alice'] = ha1('alice')
    app = protected_app(algorithm: 'SHA-256-sess')
    challenge = challenge_for(app)
    challenge['algorithm'].must_equal 'SHA-256-sess'
    header = authorization(challenge, username: 'alice', algorithm: 'SHA-256-sess')
    response = digest_get(app, header)
    response.status.must_equal 200
    response.body.must_equal 'Hi alice:'
  end

  it 'verifies the entity digest for qop=auth-int and delivers the full body' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app, method: 'POST', input: 'hello entity')
    header = authorization(challenge, username: 'alice', qop: 'auth-int',
      method: 'POST', body: 'hello entity')
    response = digest_post(app, header, 'hello entity')
    response.status.must_equal 200
    response.body.must_equal 'Hi alice:hello entity'
  end

  it 'supports qop=auth-int with an empty entity' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app, method: 'POST', input: '')
    header = authorization(challenge, username: 'alice', qop: 'auth-int',
      method: 'POST', body: '')
    response = digest_post(app, header, '')
    response.status.must_equal 200
    response.body.must_equal 'Hi alice:'
  end

  it 'rejects qop=auth-int when the entity was tampered with' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app, method: 'POST', input: 'original')
    header = authorization(challenge, username: 'alice', qop: 'auth-int',
      method: 'POST', body: 'original')
    response = digest_post(app, header, 'tampered')
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'handles usernames containing quotes and commas' do
    username = 'bob, "the builder"'
    @users[username] = ha1(username)
    app = protected_app
    challenge = challenge_for(app)
    response = digest_get(app, authorization(challenge, username: username))
    response.status.must_equal 200
    response.body.must_equal "Hi #{username}:"
  end

  it 'rechallenges without stale when the password is wrong' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    header = authorization(challenge, username: 'alice', password: 'wrong')
    response = digest_get(app, header)
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'rechallenges without stale for unknown users' do
    app = protected_app
    challenge = challenge_for(app)
    response = digest_get(app, authorization(challenge, username: 'ghost'))
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'rejects an unknown nonce without marking the challenge stale' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    header = authorization(challenge, username: 'alice', nonce: '0' * 32)
    response = digest_get(app, header)
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'rechallenges with stale=true for an expired nonce and accepts the fresh one' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    @now += 120
    response = digest_get(app, authorization(challenge, username: 'alice'))
    response.status.must_equal 401
    header = response.headers['www-authenticate']
    header.must_include 'stale=true'
    fresh = Rack::Auth::Digest::Params.parse(header.sub(/\ADigest\s+/, ''))
    fresh['nonce'].wont_equal challenge['nonce']
    ok = digest_get(app, authorization(fresh, username: 'alice'))
    ok.status.must_equal 200
    ok.body.must_equal 'Hi alice:'
  end

  it 'rejects replay of the same nonce count' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    header = authorization(challenge, username: 'alice')
    digest_get(app, header).status.must_equal 200
    replay = digest_get(app, header)
    replay.status.must_equal 401
    replay.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'accepts increasing nonce counts on the same nonce' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    digest_get(app, authorization(challenge, username: 'alice', nc: '00000001'))
      .status.must_equal 200
    digest_get(app, authorization(challenge, username: 'alice', nc: '00000002'))
      .status.must_equal 200
  end

  it 'lets only one of several concurrent requests reuse a nonce count' do
    @users['alice'] = ha1('alice')
    app = protected_app
    challenge = challenge_for(app)
    header = authorization(challenge, username: 'alice')
    statuses = []
    lock = Mutex.new
    threads = 4.times.map do
      Thread.new do
        status, = app.call(Rack::MockRequest.env_for('/', 'HTTP_AUTHORIZATION' => header))
        lock.synchronize { statuses << status }
      end
    end
    threads.each(&:join)
    statuses.count(200).must_equal 1
    statuses.count(401).must_equal 3
  end

  it 'returns 400 Bad Request for a malformed authorization header' do
    response = Rack::MockRequest.new(protected_app)
      .get('/', 'HTTP_AUTHORIZATION' => 'Digest this is not params')
    response.status.must_equal 400
    response.wont_include 'www-authenticate'
  end

  it 'returns 400 Bad Request if a different auth scheme is used' do
    response = Rack::MockRequest.new(protected_app)
      .get('/', 'HTTP_AUTHORIZATION' => 'Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==')
    response.status.must_equal 400
    response.wont_include 'www-authenticate'
  end
end
