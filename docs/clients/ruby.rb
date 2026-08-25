# frozen_string_literal: true

# jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
#
# Install: gem install rotp
#
# Env:
# * +AUTH_TOTP_SECRET+ — shared TOTP secret, base32 (required);
# * +JWT_SERVICE_URL+ — service base URL, default http://localhost:8080.
#
# The code is recomputed before every request. With replay protection on
# (+AUTH_TOTP_REPLAY_PROTECTION+) the server rejects a code it has already seen
# with 401, even while that code is still inside its time window.

require 'json'
require 'net/http'
require 'rotp'
require 'uri'

# Client of the token service, covering all four level 3 endpoints.
class JwtServiceClient
  # Sent as the Host header and becomes the +iss+ claim. Must be the same on
  # issue and on verify, or the token will not verify.
  ISSUER_HOST = 'example.com'

  # @param base_url [String] service base URL
  # @param secret [String] shared TOTP secret, base32
  def initialize(base_url, secret)
    @base_url = base_url
    @totp = ROTP::TOTP.new(secret)
  end

  # Builds a client from the environment.
  #
  # @return [JwtServiceClient]
  # @raise [KeyError] if AUTH_TOTP_SECRET is not set
  def self.from_env
    new(ENV.fetch('JWT_SERVICE_URL', 'http://localhost:8080'), ENV.fetch('AUTH_TOTP_SECRET'))
  end

  # Issues an access token (+POST /tokens+).
  #
  # @param sub [String] subject the token is issued to (+sub+ claim)
  # @param aud [Array<String>] audience (+aud+ claim), must not be empty
  # @param with_refresh [Boolean] also return a refresh token for extending the
  #   session
  # @param claims [Hash] custom claims (role, scope, tenant). They sit next to
  #   the registered ones, so the consumer reads +role+, not +extra.role+.
  #   Reserved names (+iss+, +sub+, +aud+, +exp+, +iat+, +nbf+, +jti+) are
  #   rejected with 422 — change lifetime through +ttl+, not +exp+. Count and
  #   size are capped server-side.
  # @return [Hash] +{"token" => ..., "refresh_token" => ...}+
  # @raise [RuntimeError] 401 bad code, 422 bad parameters or forbidden claim,
  #   500 JWKS or Redis unavailable
  def issue_token(sub, aud, with_refresh: false, claims: {})
    body = { sub: sub, aud: aud, refresh: with_refresh }
    body[:claims] = claims unless claims.empty?

    response = request(Net::HTTP::Post, '/tokens', body)
    raise "issue failed: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)
  end

  # Exchanges a refresh token for a new pair (+POST /tokens/refresh+).
  #
  # The old token dies on exchange: store the new one and drop the previous.
  #
  # Never retry an exchange with the old token when the reply is lost. A second
  # presentation reads as theft, and the server revokes the whole family —
  # refresh tokens and the access tokens issued from them. Issue a new pair
  # instead.
  #
  # @param refresh_token [String] token from an issue or a previous exchange
  # @return [Hash] the new pair +{"token" => ..., "refresh_token" => ...}+
  # @raise [RuntimeError] 401 — token unknown, expired or already used
  def refresh_tokens(refresh_token)
    response = request(Net::HTTP::Post, '/tokens/refresh', refresh_token: refresh_token)
    raise "refresh failed: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)
  end

  # Revokes one token by its +jti+ (+DELETE /tokens/{jti}+).
  #
  # Idempotent: revoking an unknown +jti+ is success too — the desired state
  # holds either way.
  #
  # @param jti [String] token id from the +jti+ claim
  # @return [void]
  # @raise [RuntimeError] 500 — store unreachable, the token is NOT revoked
  def revoke_token(jti)
    response = request(Net::HTTP::Delete, "/tokens/#{jti}")
    raise "revoke failed: #{response.code}" unless response.code == '204'
  end

  # Revokes every active token of a subject.
  #
  # Endpoint +DELETE /subjects/{sub}/tokens+. The compromise path: tokens cannot
  # be killed one by one because the caller does not know their +jti+.
  #
  # @param sub [String] subject whose tokens are killed
  # @return [Integer] number of revoked tokens; expired ones do not count
  # @raise [RuntimeError] 500 — store unreachable, nothing was revoked
  def revoke_subject(sub)
    response = request(Net::HTTP::Delete, "/subjects/#{sub}/tokens")
    raise "bulk revoke failed: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)['revoked']
  end

  private

  # Sends a level 3 request.
  #
  # @param klass [Class] Net::HTTP request class
  # @param path [String] endpoint path
  # @param body [Hash, nil] request body, or nil when there is none
  # @return [Net::HTTPResponse]
  def request(klass, path, body = nil)
    uri = URI.join(@base_url, path)
    req = klass.new(uri)

    # Computed here rather than reused: one code, one request.
    req['X-TOTP-Code'] = @totp.now
    req['Host'] = ISSUER_HOST
    req['Content-Type'] = 'application/json'
    req.body = JSON.dump(body) if body

    Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  end
end

if __FILE__ == $PROGRAM_NAME
  # Full token lifecycle: issue, refresh, bulk revoke.
  client = JwtServiceClient.from_env

  issued = client.issue_token('svc-a', ['svc-b'], with_refresh: true, claims: { role: 'admin' })
  puts "issued: #{issued['token'][0, 32]}..."

  refreshed = client.refresh_tokens(issued['refresh_token'])
  puts "refreshed: #{refreshed['token'][0, 32]}..."

  puts "revoked: #{client.revoke_subject('svc-a')}"
end
