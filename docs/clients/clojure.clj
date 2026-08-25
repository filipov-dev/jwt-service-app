(ns jwt-service-client
  "jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

  Dependencies: `[one-time \"0.7.0\"] [clj-http \"3.12.3\"] [cheshire \"5.12.0\"]`.

  Environment:
  - `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
  - `JWT_SERVICE_URL` — service base URL, default `http://localhost:8080`.

  The code is recomputed before every request. With replay protection on
  (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already seen
  with 401, even while that code is still inside its time window."
  (:require [cheshire.core :as json]
            [clj-http.client :as http]
            [one-time.core :as ot]))

(def ^:private issuer-host
  "Sent as the Host header and becomes the `iss` claim. Must be the same on
  issue and on verify, or the token will not verify."
  "example.com")

(defn- service-url
  "Returns the service base URL from the environment."
  []
  (or (System/getenv "JWT_SERVICE_URL") "http://localhost:8080"))

(defn totp-code
  "Computes a fresh TOTP code for right now.

  Service defaults: SHA-1, 6 digits, 30-second step.

  Returns six decimal digits."
  []
  (format "%06d" (ot/get-totp-token (System/getenv "AUTH_TOTP_SECRET"))))

(defn- request
  "Sends a level 3 request.

  `method` is :post or :delete, `path` the endpoint path, `body` the request
  body or nil. Returns the clj-http response."
  [method path body]
  (let [options (cond-> {;; Computed here rather than reused: one code, one request.
                         :headers {"X-TOTP-Code" (totp-code)
                                   "Host" issuer-host}
                         :content-type :json
                         :throw-exceptions false}
                  body (assoc :body (json/generate-string body)))]
    (http/request (merge options {:method method :url (str (service-url) path)}))))

(defn issue-token
  "Issues an access token (`POST /tokens`).

  `sub` is the subject (`sub` claim), `aud` the audience vector (`aud` claim),
  `with-refresh?` also returns a refresh token for extending the session, and
  `claims` are custom values (role, scope, tenant) placed next to the registered
  ones, so the consumer reads `role`, not `extra.role`.

  Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) give 422 —
  change lifetime through `ttl`, not `exp`. Count and size are capped
  server-side.

  Returns the parsed response body. Throws ex-info on 401 (bad code), 422 (bad
  parameters or forbidden claim) and 500 (JWKS or Redis unavailable)."
  [sub aud & {:keys [with-refresh? claims] :or {with-refresh? false claims {}}}]
  (let [body (cond-> {:sub sub :aud aud :refresh with-refresh?}
               (seq claims) (assoc :claims claims))
        response (request :post "/tokens" body)]
    (when (not= 200 (:status response))
      (throw (ex-info "issue failed" {:status (:status response)})))
    (json/parse-string (:body response))))

(defn refresh-tokens
  "Exchanges a refresh token for a new pair (`POST /tokens/refresh`).

  The old token dies on exchange: store the new one and drop the previous.

  Never retry an exchange with the old token when the reply is lost. A second
  presentation reads as theft, and the server revokes the whole family — refresh
  tokens and the access tokens issued from them. Issue a new pair instead.

  Throws ex-info on 401 — the token is unknown, expired or already used."
  [refresh-token]
  (let [response (request :post "/tokens/refresh" {:refresh_token refresh-token})]
    (when (not= 200 (:status response))
      (throw (ex-info "refresh failed" {:status (:status response)})))
    (json/parse-string (:body response))))

(defn revoke-token
  "Revokes one token by its `jti` (`DELETE /tokens/{jti}`).

  Idempotent: revoking an unknown `jti` is success too.

  Throws ex-info on 500 — the store is unreachable and the token is NOT revoked,
  retry."
  [jti]
  (let [response (request :delete (str "/tokens/" jti) nil)]
    (when (not= 204 (:status response))
      (throw (ex-info "revoke failed" {:status (:status response)})))
    nil))

(defn revoke-subject
  "Revokes every active token of a subject (`DELETE /subjects/{sub}/tokens`).

  The compromise path: tokens cannot be killed one by one because the caller
  does not know their `jti`.

  Returns the number of revoked tokens; expired ones do not count."
  [sub]
  (let [response (request :delete (str "/subjects/" sub "/tokens") nil)]
    (when (not= 200 (:status response))
      (throw (ex-info "bulk revoke failed" {:status (:status response)})))
    (get (json/parse-string (:body response)) "revoked")))

(defn -main
  "Full token lifecycle: issue, refresh, bulk revoke."
  [& _args]
  (let [issued (issue-token "svc-a" ["svc-b"] :with-refresh? true :claims {:role "admin"})
        refreshed (refresh-tokens (get issued "refresh_token"))]
    (println "issued:" (subs (get issued "token") 0 32) "...")
    (println "refreshed:" (subs (get refreshed "token") 0 32) "...")
    (println "revoked:" (revoke-subject "svc-a"))))
