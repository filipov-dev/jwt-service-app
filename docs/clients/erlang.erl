%%% @doc jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.
%%%
%%% Dependencies: standard `crypto', `httpc'; `jsx' for JSON.
%%%
%%% Env: `AUTH_TOTP_SECRET' (raw bytes here, see README.md),
%%% `JWT_SERVICE_URL' (default `http://localhost:8080').
%%%
%%% See README.md for endpoints, error codes and client rules.
%%% @end
-module(jwt_service_client).

-export([issue_token/4, refresh_tokens/1, revoke_token/1, revoke_subject/1, main/0]).

%% Sent as the Host header, becomes the `iss' claim.
-define(ISSUER_HOST, "example.com").

%% @doc Fresh TOTP code: SHA-1, 6 digits, 30-second step.
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

%% @doc `POST /tokens'.
%%
%% @param Sub Subject.
%% @param Aud Audience.
%% @param WithRefresh Also ask for a refresh token.
%% @param ClaimsJson Custom claims as a JSON binary, or `undefined'.
%% @returns `{ok, Body}' or `{error, Status}'.
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

%% @doc `POST /tokens/refresh' — returns a new pair; the old refresh token is
%% dead once the call succeeds.
%%
%% @param RefreshToken Token from an issue or a previous refresh.
%% @returns `{ok, Body}' or `{error, Status}'.
-spec refresh_tokens(string()) -> {ok, binary()} | {error, term()}.
refresh_tokens(RefreshToken) ->
    Body = iolist_to_binary(io_lib:format("{\"refresh_token\":\"~s\"}", [RefreshToken])),
    request(post, "/tokens/refresh", Body, 200).

%% @doc `DELETE /tokens/{jti}' — idempotent.
%%
%% @param Jti Token id from the `jti' claim.
%% @returns `{ok, Body}' or `{error, Status}'.
-spec revoke_token(string()) -> {ok, binary()} | {error, term()}.
revoke_token(Jti) ->
    request(delete, "/tokens/" ++ Jti, <<>>, 204).

%% @doc `DELETE /subjects/{sub}/tokens'.
%%
%% @param Sub Subject whose tokens are revoked.
%% @returns `{ok, Body}' with a `revoked' field.
-spec revoke_subject(string()) -> {ok, binary()} | {error, term()}.
revoke_subject(Sub) ->
    request(delete, "/subjects/" ++ Sub ++ "/tokens", <<>>, 200).

%% @private Sends a level 3 request with a code computed right before the call.
-spec request(atom(), string(), binary(), integer()) -> {ok, binary()} | {error, term()}.
request(Method, Path, Body, Expected) ->
    application:ensure_all_started(inets),
    Service = case os:getenv("JWT_SERVICE_URL") of
        false -> "http://localhost:8080";
        Value -> Value
    end,

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

%% @doc Issue -> refresh -> revoke.
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
