-- | Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
--
-- Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
-- токена и массовый отзыв токенов субъекта.
--
-- Зависимости: @oath@, @http-conduit@, @aeson@.
--
-- Окружение:
--
-- * @AUTH_TOTP_SECRET@ — общий TOTP-секрет (см. примечание о base32);
-- * @JWT_SERVICE_URL@ — базовый URL, по умолчанию @http:\/\/localhost:8080@.
--
-- Пример трактует секрет как сырые байты; для совместимости с Google
-- Authenticator добавьте декодер base32.
--
-- __Код считается заново перед каждым запросом.__ При включённой на сервере
-- защите от переигрывания (@AUTH_TOTP_REPLAY_PROTECTION@) повторное
-- предъявление того же кода вернёт @401@, хотя сам код ещё не истёк.
{-# LANGUAGE OverloadedStrings #-}

module Main (main) where

import Crypto.Hash.Algorithms (SHA1 (..))
import Data.Aeson (Value, encode, object, (.=))
import qualified Data.ByteString.Char8 as BS
import qualified Data.ByteString.Lazy as LBS
import Data.OTP (totp)
import Data.Time.Clock.POSIX (getPOSIXTime)
import Network.HTTP.Simple
import System.Environment (getEnv, lookupEnv)
import Text.Printf (printf)

-- | Значение claim @iss@. Должно совпадать при выпуске и проверке токена.
issuerHost :: BS.ByteString
issuerHost = "example.com"

-- | Вычисляет TOTP-код на текущий момент.
--
-- Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
-- Возвращает шестизначный код с ведущими нулями.
totpCode :: IO BS.ByteString
totpCode = do
  secret <- BS.pack <$> getEnv "AUTH_TOTP_SECRET"
  now <- round <$> getPOSIXTime
  pure . BS.pack $ printf "%06d" (totp SHA1 secret now 30 6)

-- | Базовый URL сервиса из окружения.
serviceUrl :: IO String
serviceUrl = maybe "http://localhost:8080" id <$> lookupEnv "JWT_SERVICE_URL"

-- | Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
--
-- Аргументы: HTTP-метод, путь ручки и, возможно, тело запроса. Возвращает пару
-- из HTTP-кода и тела ответа.
request :: BS.ByteString -> String -> Maybe Value -> IO (Int, LBS.ByteString)
request method path body = do
  service <- serviceUrl
  -- Код считается здесь, а не переиспользуется: один код — один запрос.
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

-- | Выпускает access-токен (@POST \/tokens@).
--
-- Аргументы: субъект (claim @sub@), получатель (claim @aud@) и признак того,
-- нужен ли refresh-токен для продления сессии.
--
-- Коды ошибок: @401@ — неверный код, @422@ — некорректные параметры,
-- @500@ — недоступны JWKS или Redis.
issueToken :: String -> String -> Bool -> IO (Int, LBS.ByteString)
issueToken sub aud withRefresh =
  request "POST" "/tokens" . Just $
    object ["sub" .= sub, "aud" .= [aud], "refresh" .= withRefresh]

-- | Обменивает refresh-токен на новую пару (@POST \/tokens\/refresh@).
--
-- Старый токен после обмена недействителен: сохраните новый и выбросьте
-- предыдущий.
--
-- __Внимание:__ не повторяйте обмен старым токеном при потере ответа. Повторное
-- предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
-- выданные по ним access-токены. Надёжнее выпустить пару заново.
--
-- Код @401@ означает, что токен неизвестен, истёк или уже использован.
refreshTokens :: String -> IO (Int, LBS.ByteString)
refreshTokens refreshToken =
  request "POST" "/tokens/refresh" . Just $ object ["refresh_token" .= refreshToken]

-- | Отзывает один токен по его @jti@ (@DELETE \/tokens\/{jti}@).
--
-- Идемпотентно: отзыв несуществующего @jti@ — тоже успех (@204@). Код @500@
-- означает, что хранилище недоступно и отзыв __не выполнен__: попытку следует
-- повторить.
revokeToken :: String -> IO (Int, LBS.ByteString)
revokeToken jti = request "DELETE" ("/tokens/" ++ jti) Nothing

-- | Отзывает все активные токены субъекта.
--
-- Ручка @DELETE \/subjects\/{sub}\/tokens@. Нужна при компрометации: гасить
-- токены по одному нельзя, их @jti@ вызывающему неизвестны. В теле ответа —
-- поле @revoked@; истёкшие токены не считаются.
revokeSubject :: String -> IO (Int, LBS.ByteString)
revokeSubject sub = request "DELETE" ("/subjects/" ++ sub ++ "/tokens") Nothing

-- | Демонстрирует полный жизненный цикл токена.
main :: IO ()
main = do
  (_, issued) <- issueToken "svc-a" "svc-b" True
  putStrLn $ "выпущен: " ++ show issued

  -- В боевом коде разберите JSON через aeson и достаньте refresh_token.
  (_, refreshed) <- refreshTokens "положите-сюда-refresh_token"
  putStrLn $ "обновлён: " ++ show refreshed

  (_, revoked) <- revokeSubject "svc-a"
  putStrLn $ "массовый отзыв: " ++ show revoked
