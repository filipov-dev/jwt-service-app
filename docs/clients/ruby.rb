# Ruby — библиотека: rotp (`gem install rotp`)
require 'rotp'
require 'net/http'
require 'json'

secret  = ENV.fetch('AUTH_TOTP_SECRET')                    # base32
service = ENV.fetch('JWT_SERVICE_URL', 'http://localhost:8080')

code = ROTP::TOTP.new(secret).now                          # SHA-1, 6, 30с

uri = URI("#{service}/tokens")
req = Net::HTTP::Post.new(uri)
req['X-TOTP-Code'] = code
req['Host'] = 'example.com'
req['Content-Type'] = 'application/json'
req.body = { sub: 'svc-a', aud: ['svc-b'] }.to_json

res = Net::HTTP.start(uri.hostname, uri.port) { |http| http.request(req) }
puts "#{res.code} #{res.body}"
