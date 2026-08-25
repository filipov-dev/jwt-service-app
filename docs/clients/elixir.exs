defmodule JwtServiceClient do
  @moduledoc """
  jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

  Dependencies: `{:nimble_totp, "~> 1.0"}`, `{:req, "~> 0.5"}`.

  Env: `AUTH_TOTP_SECRET` (base32), `JWT_SERVICE_URL` (default
  `http://localhost:8080`).

  See README.md for endpoints, error codes and client rules.
  """

  @typedoc "Reply of an issue or refresh call."
  @type token_response :: %{String.t() => String.t()}

  @issuer_host "example.com"

  @doc """
  Fresh TOTP code: SHA-1, 6 digits, 30-second step.
  """
  @spec totp_code() :: String.t()
  def totp_code do
    System.fetch_env!("AUTH_TOTP_SECRET")
    |> Base.decode32!(padding: false)
    |> NimbleTOTP.verification_code()
  end

  @doc """
  `POST /tokens`

  Returns `{:ok, body}` or `{:error, status}`.
  """
  @spec issue_token(String.t(), [String.t()], boolean(), map()) ::
          {:ok, token_response()} | {:error, integer()}
  def issue_token(sub, aud, with_refresh? \\ false, claims \\ %{}) do
    body = %{sub: sub, aud: aud, refresh: with_refresh?}
    body = if map_size(claims) > 0, do: Map.put(body, :claims, claims), else: body

    request(:post, "/tokens", body, 200)
  end

  @doc """
  `POST /tokens/refresh` — returns a new pair; the old refresh token is dead
  once the call succeeds.
  """
  @spec refresh_tokens(String.t()) :: {:ok, token_response()} | {:error, integer()}
  def refresh_tokens(refresh_token) do
    request(:post, "/tokens/refresh", %{refresh_token: refresh_token}, 200)
  end

  @doc """
  `DELETE /tokens/{jti}` — idempotent.
  """
  @spec revoke_token(String.t()) :: :ok | {:error, integer()}
  def revoke_token(jti) do
    case request(:delete, "/tokens/#{jti}", nil, 204) do
      {:ok, _} -> :ok
      error -> error
    end
  end

  @doc """
  `DELETE /subjects/{sub}/tokens` — returns the number of revoked tokens.
  """
  @spec revoke_subject(String.t()) :: {:ok, integer()} | {:error, integer()}
  def revoke_subject(sub) do
    case request(:delete, "/subjects/#{sub}/tokens", nil, 200) do
      {:ok, %{"revoked" => count}} -> {:ok, count}
      error -> error
    end
  end

  # Sends a level 3 request with a code computed right before the call.
  @spec request(atom(), String.t(), map() | nil, integer()) ::
          {:ok, map()} | {:error, integer()}
  defp request(method, path, body, expected_status) do
    service = System.get_env("JWT_SERVICE_URL", "http://localhost:8080")

    options = [
      method: method,
      url: service <> path,
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

# Issue -> refresh -> revoke.
{:ok, issued} = JwtServiceClient.issue_token("svc-a", ["svc-b"], true, %{role: "admin"})
IO.puts("issued: #{String.slice(issued["token"], 0, 32)}...")

{:ok, refreshed} = JwtServiceClient.refresh_tokens(issued["refresh_token"])
IO.puts("refreshed: #{String.slice(refreshed["token"], 0, 32)}...")

{:ok, count} = JwtServiceClient.revoke_subject("svc-a")
IO.puts("revoked: #{count}")
