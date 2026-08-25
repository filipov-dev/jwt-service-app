defmodule JwtServiceClient do
  @moduledoc """
  jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

  Dependencies: `{:nimble_totp, "~> 1.0"}`, `{:req, "~> 0.5"}`.

  ## Environment

    * `AUTH_TOTP_SECRET` — shared TOTP secret, base32 (required);
    * `JWT_SERVICE_URL` — service base URL, default `http://localhost:8080`.

  > #### One code, one request {: .warning}
  >
  > The code is recomputed before every request. With replay protection on
  > (`AUTH_TOTP_REPLAY_PROTECTION`) the server rejects a code it has already
  > seen with `401`, even while that code is still inside its time window.
  """

  @typedoc "Reply of an issue or a refresh call."
  @type token_response :: %{String.t() => String.t()}

  # Sent as the Host header and becomes the "iss" claim. Must be the same on
  # issue and on verify, or the token will not verify.
  @issuer_host "example.com"

  @doc """
  Computes a fresh TOTP code for right now.

  Service defaults: SHA-1, 6 digits, 30-second step.

  Returns six decimal digits.
  """
  @spec totp_code() :: String.t()
  def totp_code do
    System.fetch_env!("AUTH_TOTP_SECRET")
    |> Base.decode32!(padding: false)
    |> NimbleTOTP.verification_code()
  end

  @doc """
  Issues an access token (`POST /tokens`).

  ## Parameters

    * `sub` — subject the token is issued to (`sub` claim);
    * `aud` — audience (`aud` claim), must not be empty;
    * `with_refresh?` — also return a refresh token for extending the session;
    * `claims` — custom claims (role, scope, tenant) that sit next to the
      registered ones, so the consumer reads `role`, not `extra.role`.

  Reserved names (`iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`) are rejected
  with `422` — change lifetime through `ttl`, not `exp`. Count and size are
  capped server-side.

  Returns `{:ok, body}` or `{:error, status}`: `401` bad code, `422` bad
  parameters or forbidden claim, `500` JWKS or Redis unavailable.
  """
  @spec issue_token(String.t(), [String.t()], boolean(), map()) ::
          {:ok, token_response()} | {:error, integer()}
  def issue_token(sub, aud, with_refresh? \\ false, claims \\ %{}) do
    body = %{sub: sub, aud: aud, refresh: with_refresh?}
    body = if map_size(claims) > 0, do: Map.put(body, :claims, claims), else: body

    request(:post, "/tokens", body, 200)
  end

  @doc """
  Exchanges a refresh token for a new pair (`POST /tokens/refresh`).

  The old token dies on exchange: store the new one and drop the previous.

  > #### Never retry the exchange {: .error}
  >
  > When the reply is lost, do not repeat the exchange with the old token. A
  > second presentation reads as theft, and the server revokes the whole family
  > — refresh tokens and the access tokens issued from them. Issue a new pair
  > instead.

  Returns `{:ok, new_pair}` or `{:error, 401}` if the token is unknown, expired
  or already used.
  """
  @spec refresh_tokens(String.t()) :: {:ok, token_response()} | {:error, integer()}
  def refresh_tokens(refresh_token) do
    request(:post, "/tokens/refresh", %{refresh_token: refresh_token}, 200)
  end

  @doc """
  Revokes one token by its `jti` (`DELETE /tokens/{jti}`).

  Idempotent: revoking an unknown `jti` is success too.

  Returns `:ok` or `{:error, 500}` — the store is unreachable and the token is
  **not** revoked, retry.
  """
  @spec revoke_token(String.t()) :: :ok | {:error, integer()}
  def revoke_token(jti) do
    case request(:delete, "/tokens/#{jti}", nil, 204) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @doc """
  Revokes every active token of a subject (`DELETE /subjects/{sub}/tokens`).

  The compromise path: tokens cannot be killed one by one because the caller
  does not know their `jti`.

  Returns `{:ok, count}`; expired tokens do not count.
  """
  @spec revoke_subject(String.t()) :: {:ok, integer()} | {:error, integer()}
  def revoke_subject(sub) do
    case request(:delete, "/subjects/#{sub}/tokens", nil, 200) do
      {:ok, %{"revoked" => count}} -> {:ok, count}
      error -> error
    end
  end

  # Sends a level 3 request.
  @spec request(atom(), String.t(), map() | nil, integer()) ::
          {:ok, map()} | {:error, integer()}
  defp request(method, path, body, expected_status) do
    service = System.get_env("JWT_SERVICE_URL", "http://localhost:8080")

    options = [
      method: method,
      url: service <> path,
      # Computed here rather than reused: one code, one request.
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

# Full token lifecycle: issue, refresh, bulk revoke.
{:ok, issued} = JwtServiceClient.issue_token("svc-a", ["svc-b"], true, %{role: "admin"})
IO.puts("issued: #{String.slice(issued["token"], 0, 32)}...")

{:ok, refreshed} = JwtServiceClient.refresh_tokens(issued["refresh_token"])
IO.puts("refreshed: #{String.slice(refreshed["token"], 0, 32)}...")

{:ok, count} = JwtServiceClient.revoke_subject("svc-a")
IO.puts("revoked: #{count}")
