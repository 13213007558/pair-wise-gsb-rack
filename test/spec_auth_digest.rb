# frozen_string_literal: true

require_relative 'helper'

separate_testing do
  require_relative '../lib/rack/auth/digest'
  require_relative '../lib/rack/mock_request'
  require_relative '../lib/rack/lint'
end

require 'openssl'

describe Rack::Auth::Digest do
  NONCE_TTL = 300

  def realm
    'WallysWorld'
  end

  def unprotected_app
    lambda { |env|
      body = env['rack.input'] ? env['rack.input'].read : ''
      [ 200, { 'content-type' => 'text/plain' },
        ["Hi #{env['REMOTE_USER']} body=#{body.bytesize}"] ]
    }
  end

  def protected_app(**options)
    Rack::Lint.new Rack::Auth::Digest.new(unprotected_app, realm,
      nonce_store: @nonce_store,
      clock: -> { @now },
      nonce_ttl: NONCE_TTL,
      **options) { |username| @passwords[username] }
  end

  before do
    @now = Time.at(1_700_000_000)
    @passwords = { 'Boss' => 'password' }
    @nonce_store = Rack::Auth::Digest::InMemoryNonceStore.new
    @request = Rack::MockRequest.new(protected_app)
  end

  def sha256(data)
    OpenSSL::Digest::SHA256.hexdigest(data)
  end

  def parse_challenge(response)
    header = response.headers['www-authenticate']
    header.must_match(/\ADigest /)
    Rack::Auth::Digest::Params.parse(header.sub(/\ADigest\s*/, ''))
  end

  def escape_quoted(value)
    value.gsub(/["\\]/) { |char| "\\#{char}" }
  end

  # Builds an RFC 7616 Authorization header answering +challenge+.
  def authorization(challenge, username, password, method: 'GET', uri: '/',
                    qop: 'auth', algorithm: 'SHA-256', nc: '00000001',
                    cnonce: 'c0ffee', body: '')
    nonce = challenge['nonce']
    ha1 = sha256("#{username}:#{challenge['realm']}:#{password}")
    ha1 = sha256("#{ha1}:#{nonce}:#{cnonce}") if algorithm.end_with?('-sess')
    ha2 = sha256("#{method}:#{uri}")
    ha2 = sha256("#{method}:#{uri}:#{sha256(body)}") if qop == 'auth-int'
    response = sha256("#{ha1}:#{nonce}:#{nc}:#{cnonce}:#{qop}:#{ha2}")
    %(Digest username="#{escape_quoted(username)}", ) +
      %(realm="#{challenge['realm']}", nonce="#{nonce}", uri="#{uri}", ) +
      %(response="#{response}", qop=#{qop}, nc=#{nc}, cnonce="#{cnonce}", ) +
      %(algorithm=#{algorithm}, opaque="#{challenge['opaque']}")
  end

  # Performs the unauthenticated first leg of the handshake and
  # returns the parsed challenge parameters.
  def challenge_for(method: 'GET', uri: '/')
    response = method == 'GET' ? @request.get(uri) : @request.post(uri)
    response.status.must_equal 401
    parse_challenge(response)
  end

  it 'challenges with RFC 7616 parameters when no credentials are given' do
    response = @request.get('/')
    response.status.must_equal 401
    header = response.headers['www-authenticate']
    header.must_match(/\ADigest /)
    header.must_include %(realm="#{realm}")
    header.must_include 'qop="auth,auth-int"'
    header.must_include 'algorithm=SHA-256'
    header.must_include 'nonce='
    header.must_include 'opaque='
    header.wont_include 'stale'
    response.body.must_be :empty?
  end

  it 'completes a full SHA-256 auth handshake' do
    challenge = challenge_for
    auth = authorization(challenge, 'Boss', 'password')
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 200
    response.body.to_s.must_equal 'Hi Boss body=0'
  end

  it 'completes a full SHA-256-sess handshake' do
    challenge = challenge_for
    auth = authorization(challenge, 'Boss', 'password', algorithm: 'SHA-256-sess')
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 200
    response.body.to_s.must_equal 'Hi Boss body=0'
  end

  it 'verifies the entity digest with qop=auth-int and passes the full body on' do
    challenge = challenge_for(method: 'POST')
    auth = authorization(challenge, 'Boss', 'password',
      method: 'POST', qop: 'auth-int', body: 'hello world')
    response = @request.post('/', 'HTTP_AUTHORIZATION' => auth, :input => 'hello world')
    response.status.must_equal 200
    response.body.to_s.must_equal 'Hi Boss body=11'
  end

  it 'accepts an empty entity with qop=auth-int' do
    challenge = challenge_for(method: 'POST')
    auth = authorization(challenge, 'Boss', 'password',
      method: 'POST', qop: 'auth-int', body: '')
    response = @request.post('/', 'HTTP_AUTHORIZATION' => auth, :input => '')
    response.status.must_equal 200
    response.body.to_s.must_equal 'Hi Boss body=0'
  end

  it 'rejects a tampered entity with qop=auth-int' do
    challenge = challenge_for(method: 'POST')
    auth = authorization(challenge, 'Boss', 'password',
      method: 'POST', qop: 'auth-int', body: 'original')
    response = @request.post('/', 'HTTP_AUTHORIZATION' => auth, :input => 'tampered!')
    response.status.must_equal 401
  end

  it 'handles usernames containing commas and quotes' do
    username = 'Doe, "Boss"'
    @passwords[username] = 'password'
    challenge = challenge_for
    auth = authorization(challenge, username, 'password')
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 200
    response.body.to_s.must_equal "Hi #{username} body=0"
  end

  it 'rechallenges without stale when the password is wrong' do
    challenge = challenge_for
    auth = authorization(challenge, 'Boss', 'wrong')
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'rechallenges when the user is unknown' do
    challenge = challenge_for
    auth = authorization(challenge, 'ghost', 'password')
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'answers an expired nonce with stale=true and accepts the retry' do
    challenge = challenge_for
    auth = authorization(challenge, 'Boss', 'password')

    @now += NONCE_TTL + 1
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 401
    response.headers['www-authenticate'].must_include 'stale=true'

    fresh = parse_challenge(response)
    fresh['nonce'].wont_equal challenge['nonce']
    retry_auth = authorization(fresh, 'Boss', 'password')
    retry_response = @request.get('/', 'HTTP_AUTHORIZATION' => retry_auth)
    retry_response.status.must_equal 200
    retry_response.body.to_s.must_equal 'Hi Boss body=0'
  end

  it 'rejects a forged nonce without claiming staleness' do
    challenge = challenge_for
    forged = challenge.dup
    forged['nonce'] = challenge['nonce'].succ
    auth = authorization(forged, 'Boss', 'password')
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'rejects a replayed nonce count' do
    challenge = challenge_for
    auth = authorization(challenge, 'Boss', 'password')
    @request.get('/', 'HTTP_AUTHORIZATION' => auth).status.must_equal 200
    response = @request.get('/', 'HTTP_AUTHORIZATION' => auth)
    response.status.must_equal 401
    response.headers['www-authenticate'].wont_include 'stale=true'
  end

  it 'lets exactly one of many concurrent identical nonce counts through' do
    app = protected_app
    challenge = parse_challenge(Rack::MockRequest.new(app).get('/'))
    auth = authorization(challenge, 'Boss', 'password')
    statuses = Array.new(8)
    statuses.each_index.map { |index|
      Thread.new do
        statuses[index] = Rack::MockRequest.new(app).
          get('/', 'HTTP_AUTHORIZATION' => auth).status
      end
    }.each(&:join)
    statuses.count(200).must_equal 1
    statuses.count(401).must_equal 7
  end

  it 'uses the injected nonce store for replay records' do
    records = []
    store = Object.new
    store.define_singleton_method(:record) { |nonce, nc| records << [nonce, nc]; true }
    request = Rack::MockRequest.new(protected_app(nonce_store: store))
    challenge = parse_challenge(request.get('/'))
    auth = authorization(challenge, 'Boss', 'password')
    request.get('/', 'HTTP_AUTHORIZATION' => auth).status.must_equal 200
    records.must_equal [[challenge['nonce'], '00000001']]
  end

  it 'supports precomputed HA1 password lookup' do
    ha1 = sha256("Boss:#{realm}:password")
    app = Rack::Lint.new Rack::Auth::Digest.new(unprotected_app, realm,
      nonce_store: @nonce_store, clock: -> { @now },
      hashed_passwords: true) { |username| ha1 if username == 'Boss' }
    request = Rack::MockRequest.new(app)
    challenge = parse_challenge(request.get('/'))
    auth = authorization(challenge, 'Boss', 'password')
    request.get('/', 'HTTP_AUTHORIZATION' => auth).status.must_equal 200
  end

  it 'returns 400 Bad Request when a different scheme is used' do
    response = @request.get('/', 'HTTP_AUTHORIZATION' => 'Basic ' + ['u:p'].pack('m0'))
    response.status.must_equal 400
    response.wont_include 'www-authenticate'
  end

  it 'rechallenges when digest parameters are missing' do
    response = @request.get('/', 'HTTP_AUTHORIZATION' => 'Digest')
    response.status.must_equal 401
  end

  it 'takes realm as optional constructor arg' do
    app = Rack::Auth::Digest.new(unprotected_app, realm) { 'password' }
    app.realm.must_equal realm
  end
end
