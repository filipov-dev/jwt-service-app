-- Haskell — библиотека: oath (`cabal install oath`) + http-conduit
{-# LANGUAGE OverloadedStrings #-}
import Data.OTP (totp)
import Crypto.Hash.Algorithms (SHA1(..))
import qualified Data.ByteString.Char8 as BS
import Data.Time.Clock.POSIX (getPOSIXTime)
import System.Environment (lookupEnv, getEnv)
import Network.HTTP.Simple
import Text.Printf (printf)

main :: IO ()
main = do
  secret <- BS.pack <$> getEnv "AUTH_TOTP_SECRET"   -- сырые байты; для base32 декодируйте
  service <- maybe "http://localhost:8080" id <$> lookupEnv "JWT_SERVICE_URL"
  now <- round <$> getPOSIXTime
  let code = printf "%06d" (totp SHA1 secret now 30 6) :: String
  req <- parseRequest ("POST " ++ service ++ "/tokens")
  let req' = setRequestHeader "X-TOTP-Code" [BS.pack code]
           $ setRequestHeader "Host" ["example.com"]
           $ setRequestBodyLBS "{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}" req
  resp <- httpLBS req'
  print (getResponseStatusCode resp)
