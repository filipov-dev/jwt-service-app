%% Erlang — TOTP через :crypto HMAC + httpc (OTP stdlib).
%% AUTH_TOTP_SECRET ожидается как СЫРЫЕ байты (для base32 см. base32:decode/1).
-module(totp).
-export([main/0]).

main() ->
    application:ensure_all_started(inets),
    Secret = list_to_binary(os:getenv("AUTH_TOTP_SECRET")),
    Service = case os:getenv("JWT_SERVICE_URL") of false -> "http://localhost:8080"; S -> S end,

    Counter = erlang:system_time(second) div 30,
    Msg = <<Counter:64/big>>,
    Hs = crypto:mac(hmac, sha, Secret, Msg),
    Off = binary:last(Hs) band 16#0f,
    <<_:Off/binary, B0, B1, B2, B3, _/binary>> = Hs,
    Bin = ((B0 band 16#7f) bsl 24) bor (B1 bsl 16) bor (B2 bsl 8) bor B3,
    Code = lists:flatten(io_lib:format("~6..0B", [Bin rem 1000000])),

    {ok, {{_, Status, _}, _, _}} = httpc:request(post,
        {Service ++ "/tokens",
         [{"X-TOTP-Code", Code}, {"Host", "example.com"}],
         "application/json", "{\"sub\":\"svc-a\",\"aud\":[\"svc-b\"]}"},
        [], []),
    io:format("~p~n", [Status]).
