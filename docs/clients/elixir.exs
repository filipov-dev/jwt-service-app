defmodule JwtServiceClient do
  @moduledoc """
  Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).

  Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
  токена и массовый отзыв токенов субъекта.

  Зависимости: `{:nimble_totp, "~> 1.0"}`, `{:req, "~> 0.5"}`.

  ## Окружение

    * `AUTH_TOTP_SECRET` — общий TOTP-секрет в base32 (обязательно);
    * `JWT_SERVICE_URL` — базовый URL сервиса, по умолчанию `http://localhost:8080`.

  > #### Один код — один запрос {: .warning}
  >
  > Код считается заново перед каждым запросом. При включённой на сервере защите
  > от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION`) повторное предъявление того
  > же кода вернёт `401`, хотя сам код ещё не истёк.
  """

  @typedoc "Ответ на выпуск токена или обмен refresh-токена."
  @type token_response :: %{String.t() => String.t()}

  @issuer_host "example.com"

  @doc """
  Вычисляет TOTP-код на текущий момент.

  Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.

  Возвращает код из шести десятичных знаков.
  """
  @spec totp_code() :: String.t()
  def totp_code do
    System.fetch_env!("AUTH_TOTP_SECRET")
    |> Base.decode32!(padding: false)
    |> NimbleTOTP.verification_code()
  end

  @doc """
  Выпускает access-токен (`POST /tokens`).

  ## Параметры

    * `sub` — субъект, которому выдаётся токен (claim `sub`);
    * `aud` — список получателей (claim `aud`), не должен быть пустым;
    * `with_refresh?` — запросить refresh-токен для продления сессии.

  Возвращает `{:ok, тело}` либо `{:error, статус}`: `401` — неверный код,
  `422` — некорректные параметры, `500` — недоступны JWKS или Redis.
  """
  @spec issue_token(String.t(), [String.t()], boolean()) ::
          {:ok, token_response()} | {:error, integer()}
  def issue_token(sub, aud, with_refresh? \\ false) do
    request(:post, "/tokens", %{sub: sub, aud: aud, refresh: with_refresh?}, 200)
  end

  @doc """
  Обменивает refresh-токен на новую пару (`POST /tokens/refresh`).

  Старый токен после обмена недействителен: сохраните новый и выбросьте
  предыдущий.

  > #### Не ретрайте обмен {: .error}
  >
  > При потере ответа не повторяйте обмен старым токеном. Повторное предъявление
  > трактуется как кража и гасит всю семью — и refresh-токены, и выданные по ним
  > access-токены. Надёжнее выпустить пару заново.

  Возвращает `{:ok, новая_пара}` либо `{:error, 401}`, если токен неизвестен,
  истёк или уже использован.
  """
  @spec refresh_tokens(String.t()) :: {:ok, token_response()} | {:error, integer()}
  def refresh_tokens(refresh_token) do
    request(:post, "/tokens/refresh", %{refresh_token: refresh_token}, 200)
  end

  @doc """
  Отзывает один токен по его `jti` (`DELETE /tokens/{jti}`).

  Идемпотентно: отзыв несуществующего `jti` — тоже успех.

  Возвращает `:ok` либо `{:error, 500}`, если хранилище недоступно и отзыв **не
  выполнен** — попытку следует повторить.
  """
  @spec revoke_token(String.t()) :: :ok | {:error, integer()}
  def revoke_token(jti) do
    case request(:delete, "/tokens/#{jti}", nil, 204) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @doc """
  Отзывает все активные токены субъекта (`DELETE /subjects/{sub}/tokens`).

  Нужен при компрометации: гасить токены по одному нельзя, их `jti` вызывающему
  неизвестны.

  Возвращает `{:ok, количество}`; уже истёкшие токены не считаются.
  """
  @spec revoke_subject(String.t()) :: {:ok, integer()} | {:error, integer()}
  def revoke_subject(sub) do
    case request(:delete, "/subjects/#{sub}/tokens", nil, 200) do
      {:ok, %{"revoked" => count}} -> {:ok, count}
      error -> error
    end
  end

  # Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
  @spec request(atom(), String.t(), map() | nil, integer()) ::
          {:ok, map()} | {:error, integer()}
  defp request(method, path, body, expected_status) do
    service = System.get_env("JWT_SERVICE_URL", "http://localhost:8080")

    options = [
      method: method,
      url: service <> path,
      # Код считается здесь, а не переиспользуется: один код — один запрос.
      headers: [{"x-totp-code", totp_code()}, {"host", @issuer_host}]
    ]

    options = if body, do: Keyword.put(options, :json, body), else: options

    case Req.request(options) do
      {:ok, %{status: ^expected_status, body: response_body}} -> {:ok, response_body}
      {:ok, %{status: status}} -> {:error, status}
      {:error, reason} -> {:error, reason}
    end
  end
end

# Демонстрация полного жизненного цикла токена.
{:ok, issued} = JwtServiceClient.issue_token("svc-a", ["svc-b"], true)
IO.puts("выпущен: #{String.slice(issued["token"], 0, 32)}...")

{:ok, refreshed} = JwtServiceClient.refresh_tokens(issued["refresh_token"])
IO.puts("обновлён: #{String.slice(refreshed["token"], 0, 32)}...")

{:ok, count} = JwtServiceClient.revoke_subject("svc-a")
IO.puts("отозвано токенов: #{count}")
