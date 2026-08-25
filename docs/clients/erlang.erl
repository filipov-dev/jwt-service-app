%%% @doc jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
%%%
%%% Dependencies: standard `crypto', `httpc'; `jsx' for JSON.
%%%
%%% Environment:
%%% <ul>
%%%   <li>`AUTH_TOTP_SECRET' — shared TOTP secret (see the base32 note below);</li>
%%%   <li>`JWT_SERVICE_URL' — base URL, default `http://localhost:8080'.</li>
%%% </ul>
%%%
%%% This example treats the secret as raw bytes. Add a base32 decoder for
%%% Google Authenticator compatibility.
%%%
%%% <b>The code is recomputed before every request.</b> With replay protection
%%% on (`AUTH_TOTP_REPLAY_PROTECTION') the server rejects a code it has already
%%% seen with `401', even while that code is still inside its time window.
%%% @end
-module(jwt_service_client).

-export([issue_token/4, refresh_tokens/1, revoke_token/1, revoke_subject/1, main/0]).

%% Sent as the Host header and becomes the `iss' claim. Must be the same on
%% issue and on verify, or the token will not verify.
-define(ISSUER_HOST, "example.com").

%% @doc Computes a fresh TOTP code for right now.
%%
%% Service defaults: SHA-1, 6 digits, 30-second step.
%%
%% @returns Six decimal digits.
-spec totp_code() -> string().
totp_code() ->
    Secret = list_to_binary(os:getenv("AUTH_TOTP_SECRET")),
    Counter = erlang:system_time(second) div 30,
    Hmac = crypto:mac(hmac, sha, Secret, <<Counter:64/big>>),

    %% Dynamic truncation, RFC 4226 section 5.3.
    Offset = binary:last(Hmac) band 16#0f,
    <<_:Offset/binary, B0, B1, B2, B3, _/binary>> = Hmac,
    Code = ((B0 band 16#7f) bsl 24) bor (B1 bsl 16) bor (B2 bsl 8) bor B3,

    lists:flatten(io_lib:format("~6..0B", [Code rem 1000000])).

%% @doc Issues an access token (`POST /tokens').
%%
%% @param Sub Subject the token is issued to (`sub' claim).
%% @param Aud Audience (`aud' claim).
%% @param WithRefresh Also return a refresh token for extending the session.
%% @param ClaimsJson Custom claims as a JSON binary (for example
%%        `<<"{\"role\":\"admin\"}">>') or `undefined'. They sit next to the
%%        registered ones; reserved names (`iss', `sub', `aud', `exp', `iat',
%%        `nbf', `jti') give `422' — change lifetime through `ttl', not `exp'.
%% @returns `{ok, Body}' or `{error, Status}': `401' bad code, `422' bad
%%          parameters or forbidden claim, `500' JWKS or Redis unavailable.
-spec issue_token(string(), string(), boolean(), binary() | undefined) ->
    {ok, binary()} | {error, term()}.
issue_token(Sub, Aud, WithRefresh, ClaimsJson) ->
    ClaimsPart = case ClaimsJson of
        undefined -> <<>>;
        Json -> iolist_to_binary([<<",\"claims\":">>, Json])
    end,
    Body = iolist_to_binary([
        io_lib:format("{\"sub\":\"~s\",\"aud\":[\"~s\"],\"refresh\":~p", [Sub, Aud, WithRefresh]),
        ClaimsPart,
        <<"}">>
    ]),
    request(post, "/tokens", Body, 200).

%% @doc Exchanges a refresh token for a new pair (`POST /tokens/refresh').
%%
%% The old token dies on exchange: store the new one and drop the previous.
%%
%% <b>Never retry</b> an exchange with the old token when the reply is lost. A
%% second presentation reads as theft, and the server revokes the whole family —
%% refresh tokens and the access tokens issued from them. Issue a new pair
%% instead.
%%
%% @param RefreshToken Token from an issue or a previous exchange.
%% @returns `{ok, Body}' or `{error, 401}' if the token is unknown, expired or
%%          already used.
-spec refresh_tokens(string()) -> {ok, binary()} | {error, term()}.
refresh_tokens(RefreshToken) ->
    Body = iolist_to_binary(io_lib:format("{\"refresh_token\":\"~s\"}", [RefreshToken])),
    request(post, "/tokens/refresh", Body, 200).

%% @doc Revokes one token by its `jti' (`DELETE /tokens/{jti}').
%%
%% Idempotent: revoking an unknown `jti' is success too.
%%
%% @param Jti Token id from the `jti' claim.
%% @returns `{ok, _}' or `{error, 500}' — the store is unreachable and the token
%%          is NOT revoked, retry.
-spec revoke_token(string()) -> {ok, binary()} | {error, term()}.
revoke_token(Jti) ->
    request(delete, "/tokens/" ++ Jti, <<>>, 204).

%% @doc Revokes every active token of a subject.
%%
%% Endpoint `DELETE /subjects/{sub}/tokens'. The compromise path: tokens cannot
%% be killed one by one because the caller does not know their `jti'.
%%
%% @param Sub Subject whose tokens are killed.
%% @returns `{ok, Body}' with a `revoked' field; expired tokens do not count.
-spec revoke_subject(string()) -> {ok, binary()} | {error, term()}.
revoke_subject(Sub) ->
    request(delete, "/subjects/" ++ Sub ++ "/tokens", <<>>, 200).

%% @private Sends a level 3 request.
-spec request(atom(), string(), binary(), integer()) -> {ok, binary()} | {error, term()}.
request(Method, Path, Body, Expected) ->
    application:ensure_all_started(inets),
    Service = case os:getenv("JWT_SERVICE_URL") of
        false -> "http://localhost:8080";
        Value -> Value
    end,

    %% Computed here rather than reused: one code, one request.
    Headers = [{"X-TOTP-Code", totp_code()}, {"Host", ?ISSUER_HOST}],
    Request = {Service ++ Path, Headers, "application/json", Body},

    case httpc:request(Method, Request, [], []) of
        {ok, {{_, Status, _}, _, ResponseBody}} when Status =:= Expected ->
            {ok, list_to_binary(ResponseBody)};
        {ok, {{_, Status, _}, _, _}} ->
            {error, Status};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc Full token lifecycle: issue, refresh, bulk revoke.
-spec main() -> ok.
main() ->
    {ok, Issued} = issue_token("svc-a", "svc-b", true, <<"{\"role\":\"admin\"}">>),
    io:format("issued: ~s~n", [Issued]),

    %% Real code should parse the JSON with a library (jsx, for example) and
    %% take refresh_token from the reply.
    {ok, Refreshed} = refresh_tokens("put-refresh-token-here"),
    io:format("refreshed: ~s~n", [Refreshed]),

    {ok, Revoked} = revoke_subject("svc-a"),
    io:format("bulk revoke: ~s~n", [Revoked]).
