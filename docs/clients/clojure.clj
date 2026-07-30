(ns jwt-service-client
  "Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).

  Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
  токена и массовый отзыв токенов субъекта.

  Зависимости: `[one-time \"0.7.0\"] [clj-http \"3.12.3\"] [cheshire \"5.12.0\"]`.

  Окружение:
  - `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
  - `JWT_SERVICE_URL` — базовый URL сервиса, по умолчанию `http://localhost:8080`.

  ВАЖНО: код считается заново перед каждым запросом. При включённой на сервере
  защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление
  того же кода вернёт 401, хотя сам код ещё не истёк."
  (:require [cheshire.core :as json]
            [clj-http.client :as http]
            [one-time.core :as ot]))

(def ^:private issuer-host
  "Значение claim `iss`. Должно совпадать при выпуске и проверке токена."
  "example.com")

(defn- service-url
  "Возвращает базовый URL сервиса из окружения."
  []
  (or (System/getenv "JWT_SERVICE_URL") "http://localhost:8080"))

(defn totp-code
  "Вычисляет TOTP-код на текущий момент.

  Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.

  Возвращает строку из шести десятичных знаков."
  []
  (format "%06d" (ot/get-totp-token (System/getenv "AUTH_TOTP_SECRET"))))

(defn- request
  "Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.

  `method` — ключевое слово (:post или :delete), `path` — путь ручки,
  `body` — тело запроса либо nil. Возвращает ответ clj-http."
  [method path body]
  (let [options (cond-> {;; Код считается здесь: один код — один запрос.
                         :headers {"X-TOTP-Code" (totp-code)
                                   "Host" issuer-host}
                         :content-type :json
                         :throw-exceptions false}
                  body (assoc :body (json/generate-string body)))]
    (http/request (merge options {:method method :url (str (service-url) path)}))))

(defn issue-token
  "Выпускает access-токен (`POST /tokens`).

  `sub` — субъект (claim `sub`), `aud` — вектор получателей (claim `aud`),
  `with-refresh?` — запросить refresh-токен для продления сессии,
  `claims` — произвольные claims (роли, scope, tenant), попадают в payload рядом
  с зарегистрированными.

  Служебные имена (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`)
  переопределять нельзя — сервис ответит 422. Число ключей и объём ограничены на
  сервере.

  Возвращает распарсенное тело ответа. Бросает ex-info при 401 (неверный код),
  422 (некорректные параметры или запрещённый claim) и 500 (JWKS или Redis)."
  [sub aud & {:keys [with-refresh? claims] :or {with-refresh? false claims {}}}]
  (let [body (cond-> {:sub sub :aud aud :refresh with-refresh?}
               (seq claims) (assoc :claims claims))
        response (request :post "/tokens" body)]
    (when (not= 200 (:status response))
      (throw (ex-info "выпуск не удался" {:status (:status response)})))
    (json/parse-string (:body response))))

(defn refresh-tokens
  "Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).

  Старый токен после обмена недействителен: сохраните новый и выбросьте
  предыдущий.

  ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
  предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
  выданные по ним access-токены. Надёжнее выпустить пару заново.

  Бросает ex-info при 401 — токен неизвестен, истёк или уже использован."
  [refresh-token]
  (let [response (request :post "/tokens/refresh" {:refresh_token refresh-token})]
    (when (not= 200 (:status response))
      (throw (ex-info "обмен не удался" {:status (:status response)})))
    (json/parse-string (:body response))))

(defn revoke-token
  "Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).

  Идемпотентно: отзыв несуществующего `jti` — тоже успех.

  Бросает ex-info при 500 — хранилище недоступно, отзыв НЕ выполнен."
  [jti]
  (let [response (request :delete (str "/tokens/" jti) nil)]
    (when (not= 204 (:status response))
      (throw (ex-info "отзыв не удался" {:status (:status response)})))
    nil))

(defn revoke-subject
  "Отзывает все активные токены субъекта (`DELETE /subjects/{sub}/tokens`).

  Нужен при компрометации: гасить токены по одному нельзя, их `jti` вызывающему
  неизвестны.

  Возвращает число отозванных токенов; истёкшие не считаются."
  [sub]
  (let [response (request :delete (str "/subjects/" sub "/tokens") nil)]
    (when (not= 200 (:status response))
      (throw (ex-info "массовый отзыв не удался" {:status (:status response)})))
    (get (json/parse-string (:body response)) "revoked")))

(defn -main
  "Демонстрирует полный жизненный цикл токена."
  [& _args]
  (let [issued (issue-token "svc-a" ["svc-b"] :with-refresh? true :claims {:role "admin"})
        refreshed (refresh-tokens (get issued "refresh_token"))]
    (println "выпущен:" (subs (get issued "token") 0 32) "...")
    (println "обновлён:" (subs (get refreshed "token") 0 32) "...")
    (println "отозвано токенов:" (revoke-subject "svc-a"))))
