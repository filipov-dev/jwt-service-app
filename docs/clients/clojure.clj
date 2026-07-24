;; Clojure — библиотека: one-time (`[one-time "0.7.0"]`) + clj-http
(require '[one-time.core :as ot]
         '[clj-http.client :as http])

(let [secret  (System/getenv "AUTH_TOTP_SECRET")               ; base32
      service (or (System/getenv "JWT_SERVICE_URL") "http://localhost:8080")
      code    (format "%06d" (ot/get-totp-token secret))]      ; SHA-1, 6, 30с
  (println
    (:status (http/post (str service "/tokens")
               {:headers {"X-TOTP-Code" code "Host" "example.com"}
                :content-type :json
                :body "{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}"
                :throw-exceptions false}))))
