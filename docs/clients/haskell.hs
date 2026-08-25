-- | jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
--
-- Dependencies: @oath@, @http-conduit@, @aeson@.
--
-- Environment:
--
-- * @AUTH_TOTP_SECRET@ — shared TOTP secret (see the base32 note below);
-- * @JWT_SERVICE_URL@ — base URL, default @http:\/\/localhost:8080@.
--
-- This example treats the secret as raw bytes; add a base32 decoder for Google
-- Authenticator compatibility.
--
-- __The code is recomputed before every request.__ With replay protection on
-- (@AUTH_TOTP_REPLAY_PROTECTION@) the server rejects a code it has already seen
-- with @401@, even while that code is still inside its time window.
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto.Hash.Algorithms (SHA1 (..))
import Data.Aeson (Value, encode, object, (.=))
import Data.Aeson.Types (Pair)
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as LBS
import Data.OTP (totp)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Simple
import System.Environment (getEnv, lookupEnv)
import Text.Printf (printf)

-- | Sent as the Host header and becomes the @iss@ claim. Must be the same on
-- issue and on verify, or the token will not verify.
issuerHost :: BS.ByteString
issuerHost = "example.com"

-- | Computes a fresh TOTP code for right now.
--
-- Service defaults: SHA-1, 6 digits, 30-second step. Returns six digits with
-- leading zeroes.
totpCode :: IO BS.ByteString
totpCode = do
  secret <- BS.pack <$> getEnv "AUTH_TOTP_SECRET"
  now <- round <$> getPOSIXTime
  pure . BS.pack $ printf "%06d" (totp SHA1 secret now 30 6)

-- | Service base URL from the environment.
serviceUrl :: IO String
serviceUrl = maybe "http://localhost:8080" id <$> lookupEnv "JWT_SERVICE_URL"

-- | Sends a level 3 request.
--
-- Takes the HTTP method, the endpoint path and an optional body. Returns the
-- HTTP status and the response body.
request :: BS.ByteString -> String -> Maybe Value -> IO (Int, LBS.ByteString)
request method path body = do
  service <- serviceUrl
  -- Computed here rather than reused: one code, one request.
  code <- totpCode

  initial <- parseRequest (service ++ path)
  let prepared =
        setRequestMethod method
          . setRequestHeader "X-TOTP-Code" [code]
          . setRequestHeader "Host" [issuerHost]
          . setRequestHeader "Content-Type" ["application/json"]
          $ maybe initial (\b -> setRequestBodyLBS (encode b) initial) body

  response <- httpLBS prepared
  pure (getResponseStatusCode response, getResponseBody response)

-- | Issues an access token (@POST \/tokens@).
--
-- Takes the subject (@sub@ claim), the audience (@aud@ claim), whether a
-- refresh token is wanted for extending the session, and the custom claims
-- (empty list for none).
--
-- Custom claims sit next to the registered ones, so the consumer reads @role@,
-- not @extra.role@. Reserved names (@iss@, @sub@, @aud@, @exp@, @iat@, @nbf@,
-- @jti@) give @422@ — change lifetime through @ttl@, not @exp@.
--
-- Statuses: @401@ bad code, @422@ bad parameters or forbidden claim, @500@ JWKS
-- or Redis unavailable.
issueToken :: String -> String -> Bool -> [Pair] -> IO (Int, LBS.ByteString)
issueToken sub aud withRefresh claims =
  request "POST" "/tokens" . Just . object $
    ["sub" .= sub, "aud" .= [aud], "refresh" .= withRefresh]
      ++ ["claims" .= object claims | not (null claims)]

-- | Exchanges a refresh token for a new pair (@POST \/tokens\/refresh@).
--
-- The old token dies on exchange: store the new one and drop the previous.
--
-- __Never retry__ an exchange with the old token when the reply is lost. A
-- second presentation reads as theft, and the server revokes the whole family —
-- refresh tokens and the access tokens issued from them. Issue a new pair
-- instead.
--
-- @401@ means the token is unknown, expired or already used.
refreshTokens :: String -> IO (Int, LBS.ByteString)
refreshTokens refreshToken =
  request "POST" "/tokens/refresh" . Just $ object ["refresh_token" .= refreshToken]

-- | Revokes one token by its @jti@ (@DELETE \/tokens\/{jti}@).
--
-- Idempotent: revoking an unknown @jti@ is success too (@204@). @500@ means the
-- store is unreachable and the token is __not__ revoked: retry.
revokeToken :: String -> IO (Int, LBS.ByteString)
revokeToken jti = request "DELETE" ("/tokens/" ++ jti) Nothing

-- | Revokes every active token of a subject.
--
-- Endpoint @DELETE \/subjects\/{sub}\/tokens@. The compromise path: tokens
-- cannot be killed one by one because the caller does not know their @jti@. The
-- reply carries a @revoked@ field; expired tokens do not count.
revokeSubject :: String -> IO (Int, LBS.ByteString)
revokeSubject sub = request "DELETE" ("/subjects/" ++ sub ++ "/tokens") Nothing

-- | Full token lifecycle: issue, refresh, bulk revoke.
main :: IO ()
main = do
  (_, issued) <- issueToken "svc-a" "svc-b" True ["role" .= ("admin" :: String)]
  putStrLn $ "issued: " ++ show issued

  -- Real code should parse the JSON with aeson and take refresh_token from it.
  (_, refreshed) <- refreshTokens "put-refresh-token-here"
  putStrLn $ "refreshed: " ++ show refreshed

  (_, revoked) <- revokeSubject "svc-a"
  putStrLn $ "bulk revoke: " ++ show revoked
