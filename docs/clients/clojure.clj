(ns jwt-service-client
  "jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

  Dependencies: `[one-time \"0.7.0\"] [clj-http \"3.12.3\"] [cheshire \"5.12.0\"]`.

  Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
  `http://localhost:8080`).

  See README.md for endpoints, error codes and client rules."
  (:require [cheshire.core :as json]
            [clj-http.client :as http]
            [one-time.core :as ot]))

(def ^:private issuer-host
  "Sent as the Host header, becomes the `iss` claim."
  "example.com")

(defn- service-url
  "Service base URL from the environment."
  []
  (or (System/getenv "JWT_SERVICE_URL") "http://localhost:8080"))

(defn totp-code
  "Fresh TOTP code: SHA-1, 6 digits, 30-second step."
  []
  (format "%06d" (ot/get-totp-token (System/getenv "AUTH_TOTP_SECRET"))))

(defn- request
  "Sends a level 3 request with a code computed right before the call.

  `method` is :post or :delete, `path` is the endpoint path, `body` may be nil.
  Returns the clj-http response."
  [method path body]
  (let [options (cond-> {:headers {"X-TOTP-Code" (totp-code)
                                   "Host" issuer-host}
                         :content-type :json
                         :throw-exceptions false}
                  body (assoc :body (json/generate-string body)))]
    (http/request (merge options {:method method :url (str (service-url) path)}))))

(defn issue-token
  "`POST /tokens` — returns the parsed response body.

  `sub` subject, `aud` audience vector, `with-refresh?` also asks for a refresh
  token, `claims` are custom claims."
  [sub aud & {:keys [with-refresh? claims] :or {with-refresh? false claims {}}}]
  (let [body (cond-> {:sub sub :aud aud :refresh with-refresh?}
               (seq claims) (assoc :claims claims))
        response (request :post "/tokens" body)]
    (when (not= 200 (:status response))
      (throw (ex-info "issue failed" {:status (:status response)})))
    (json/parse-string (:body response))))

(defn refresh-tokens
  "`POST /tokens/refresh` — returns a new pair; the old refresh token is dead
  once the call succeeds."
  [refresh-token]
  (let [response (request :post "/tokens/refresh" {:refresh_token refresh-token})]
    (when (not= 200 (:status response))
      (throw (ex-info "refresh failed" {:status (:status response)})))
    (json/parse-string (:body response))))

(defn revoke-token
  "`DELETE /tokens/{jti}` — idempotent."
  [jti]
  (let [response (request :delete (str "/tokens/" jti) nil)]
    (when (not= 204 (:status response))
      (throw (ex-info "revoke failed" {:status (:status response)})))
    nil))

(defn revoke-subject
  "`DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens."
  [sub]
  (let [response (request :delete (str "/subjects/" sub "/tokens") nil)]
    (when (not= 200 (:status response))
      (throw (ex-info "bulk revoke failed" {:status (:status response)})))
    (get (json/parse-string (:body response)) "revoked")))

(defn -main
  "Issue -> refresh -> revoke."
  [& _args]
  (let [issued (issue-token "svc-a" ["svc-b"] :with-refresh? true :claims {:role "admin"})
        refreshed (refresh-tokens (get issued "refresh_token"))]
    (println "issued:" (subs (get issued "token") 0 32) "...")
    (println "refreshed:" (subs (get refreshed "token") 0 32) "...")
    (println "revoked:" (revoke-subject "svc-a"))))
