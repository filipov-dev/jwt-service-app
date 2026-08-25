-- | jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
--
-- Dependencies: @oath@, @http-conduit@, @aeson@.
--
-- Env: @AUTH_TOTP_SECRET@ (raw bytes here, see README.md), @JWT_SERVICE_URL@
-- (default @http:\/\/localhost:8080@).
--
-- See README.md for endpoints, error codes and client rules.
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

-- | Sent as the Host header, becomes the @iss@ claim.
issuerHost :: BS.ByteString
issuerHost = "example.com"

-- | Fresh TOTP code: SHA-1, 6 digits, 30-second step.
totpCode :: IO BS.ByteString
totpCode = do
  secret <- BS.pack <$> getEnv "AUTH_TOTP_SECRET"
  now <- round <$> getPOSIXTime
  pure . BS.pack $ printf "%06d" (totp SHA1 secret now 30 6)

-- | Service base URL from the environment.
serviceUrl :: IO String
serviceUrl = maybe "http://localhost:8080" id <$> lookupEnv "JWT_SERVICE_URL"

-- | Sends a level 3 request with a code computed right before the call.
--
-- Takes the HTTP method, the endpoint path and an optional body; returns the
-- HTTP status and the response body.
request :: BS.ByteString -> String -> Maybe Value -> IO (Int, LBS.ByteString)
request method path body = do
  service <- serviceUrl
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

-- | @POST \/tokens@
--
-- Takes the subject, the audience, whether a refresh token is wanted, and the
-- custom claims (empty list for none).
issueToken :: String -> String -> Bool -> [Pair] -> IO (Int, LBS.ByteString)
issueToken sub aud withRefresh claims =
  request "POST" "/tokens" . Just . object $
    ["sub" .= sub, "aud" .= [aud], "refresh" .= withRefresh]
      ++ ["claims" .= object claims | not (null claims)]

-- | @POST \/tokens\/refresh@ — returns a new pair; the old refresh token is
-- dead once the call succeeds.
refreshTokens :: String -> IO (Int, LBS.ByteString)
refreshTokens refreshToken =
  request "POST" "/tokens/refresh" . Just $ object ["refresh_token" .= refreshToken]

-- | @DELETE \/tokens\/{jti}@ — idempotent.
revokeToken :: String -> IO (Int, LBS.ByteString)
revokeToken jti = request "DELETE" ("/tokens/" ++ jti) Nothing

-- | @DELETE \/subjects\/{sub}\/tokens@ — the reply carries a @revoked@ field.
revokeSubject :: String -> IO (Int, LBS.ByteString)
revokeSubject sub = request "DELETE" ("/subjects/" ++ sub ++ "/tokens") Nothing

-- | Issue -> refresh -> revoke.
main :: IO ()
main = do
  (_, issued) <- issueToken "svc-a" "svc-b" True ["role" .= ("admin" :: String)]
  putStrLn $ "issued: " ++ show issued

  -- Real code should parse the JSON with aeson and take refresh_token from it.
  (_, refreshed) <- refreshTokens "put-refresh-token-here"
  putStrLn $ "refreshed: " ++ show refreshed

  (_, revoked) <- revokeSubject "svc-a"
  putStrLn $ "bulk revoke: " ++ show revoked
