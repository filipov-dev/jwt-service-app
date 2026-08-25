# frozen_string_literal: true

# jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
#
# Install: gem install rotp
# Env: +AUTH_TOTP_SECRET+ (base32), +JWT_SERVICE_URL+ (default
# http://localhost:8080).
# See README.md for endpoints, error codes and client rules.

require 'json'
require 'net/http'
require 'rotp'
require 'uri'

# Client of the token service.
class JwtServiceClient
  # Sent as the Host header, becomes the +iss+ claim.
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
  def self.from_env
    new(ENV.fetch('JWT_SERVICE_URL', 'http://localhost:8080'), ENV.fetch('AUTH_TOTP_SECRET'))
  end

  # +POST /tokens+
  #
  # @param sub [String]
  # @param aud [Array<String>]
  # @param with_refresh [Boolean]
  # @param claims [Hash]
  # @return [Hash] +{"token" => ..., "refresh_token" => ...}+
  def issue_token(sub, aud, with_refresh: false, claims: {})
    body = { sub: sub, aud: aud, refresh: with_refresh }
    body[:claims] = claims unless claims.empty?

    response = request(Net::HTTP::Post, '/tokens', body)
    raise "issue failed: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)
  end

  # +POST /tokens/refresh+ — returns a new pair; the old refresh token is dead.
  #
  # @param refresh_token [String]
  # @return [Hash] +{"token" => ..., "refresh_token" => ...}+
  def refresh_tokens(refresh_token)
    response = request(Net::HTTP::Post, '/tokens/refresh', refresh_token: refresh_token)
    raise "refresh failed: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)
  end

  # +DELETE /tokens/{jti}+ — idempotent.
  #
  # @param jti [String]
  # @return [void]
  def revoke_token(jti)
    response = request(Net::HTTP::Delete, "/tokens/#{jti}")
    raise "revoke failed: #{response.code}" unless response.code == '204'
  end

  # +DELETE /subjects/{sub}/tokens+
  #
  # @param sub [String]
  # @return [Integer] number of revoked tokens
  def revoke_subject(sub)
    response = request(Net::HTTP::Delete, "/subjects/#{sub}/tokens")
    raise "bulk revoke failed: #{response.code}" unless response.code == '200'

    JSON.parse(response.body)['revoked']
  end

  private

  # Sends a level 3 request with a code computed right before the call.
  #
  # @param klass [Class] Net::HTTP request class
  # @param path [String] endpoint path
  # @param body [Hash, nil] request body, if any
  # @return [Net::HTTPResponse]
  def request(klass, path, body = nil)
    uri = URI.join(@base_url, path)
    req = klass.new(uri)

    req['X-TOTP-Code'] = @totp.now
    req['Host'] = ISSUER_HOST
    req['Content-Type'] = 'application/json'
    req.body = JSON.dump(body) if body

    Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
  end
end

if __FILE__ == $PROGRAM_NAME
  client = JwtServiceClient.from_env

  issued = client.issue_token('svc-a', ['svc-b'], with_refresh: true, claims: { role: 'admin' })
  puts "issued: #{issued['token'][0, 32]}..."

  refreshed = client.refresh_tokens(issued['refresh_token'])
  puts "refreshed: #{refreshed['token'][0, 32]}..."

  puts "revoked: #{client.revoke_subject('svc-a')}"
end
