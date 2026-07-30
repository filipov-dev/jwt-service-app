%%% @doc Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
%%%
%%% Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
%%% токена и массовый отзыв токенов субъекта.
%%%
%%% Зависимости: стандартные `crypto', `httpc'; для разбора JSON — `jsx'.
%%%
%%% Окружение:
%%% <ul>
%%%   <li>`AUTH_TOTP_SECRET' — общий TOTP-секрет (см. примечание о base32);</li>
%%%   <li>`JWT_SERVICE_URL' — базовый URL, по умолчанию `http://localhost:8080'.</li>
%%% </ul>
%%%
%%% Пример трактует секрет как сырые байты. Для совместимости с Google
%%% Authenticator добавьте декодер base32.
%%%
%%% <b>Код считается заново перед каждым запросом.</b> При включённой на сервере
%%% защите от переигрывания (`AUTH_TOTP_REPLAY_PROTECTION') повторное
%%% предъявление того же кода вернёт `401', хотя сам код ещё не истёк.
%%% @end
-module(jwt_service_client).

-export([issue_token/3, refresh_tokens/1, revoke_token/1, revoke_subject/1, main/0]).

%% Значение claim `iss'. Должно совпадать при выпуске и проверке токена.
-define(ISSUER_HOST, "example.com").

%% @doc Вычисляет TOTP-код на текущий момент.
%%
%% Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
%%
%% @returns Код из шести десятичных знаков.
-spec totp_code() -> string().
totp_code() ->
    Secret = list_to_binary(os:getenv("AUTH_TOTP_SECRET")),
    Counter = erlang:system_time(second) div 30,
    Hmac = crypto:mac(hmac, sha, Secret, <<Counter:64/big>>),

    %% Динамическое усечение по RFC 4226 §5.3.
    Offset = binary:last(Hmac) band 16#0f,
    <<_:Offset/binary, B0, B1, B2, B3, _/binary>> = Hmac,
    Code = ((B0 band 16#7f) bsl 24) bor (B1 bsl 16) bor (B2 bsl 8) bor B3,

    lists:flatten(io_lib:format("~6..0B", [Code rem 1000000])).

%% @doc Выпускает access-токен (`POST /tokens').
%%
%% @param Sub Субъект, которому выдаётся токен (claim `sub').
%% @param Aud Получатель (claim `aud').
%% @param WithRefresh Запросить refresh-токен для продления сессии.
%% @returns `{ok, Body}' либо `{error, Status}': `401' — неверный код,
%%          `422' — некорректные параметры, `500' — JWKS или Redis недоступны.
-spec issue_token(string(), string(), boolean()) -> {ok, binary()} | {error, term()}.
issue_token(Sub, Aud, WithRefresh) ->
    Body = iolist_to_binary(io_lib:format(
        "{\"sub\":\"~s\",\"aud\":[\"~s\"],\"refresh\":~p}", [Sub, Aud, WithRefresh])),
    request(post, "/tokens", Body, 200).

%% @doc Обменивает refresh-токен на новую пару (`POST /tokens/refresh').
%%
%% Старый токен после обмена недействителен: сохраните новый и выбросьте
%% предыдущий.
%%
%% <b>Внимание:</b> не повторяйте обмен старым токеном при потере ответа.
%% Повторное предъявление трактуется как кража и гасит всю семью — и
%% refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
%% заново.
%%
%% @param RefreshToken Токен из выпуска или прошлого обмена.
%% @returns `{ok, Body}' либо `{error, 401}', если токен неизвестен, истёк или
%%          уже использован.
-spec refresh_tokens(string()) -> {ok, binary()} | {error, term()}.
refresh_tokens(RefreshToken) ->
    Body = iolist_to_binary(io_lib:format("{\"refresh_token\":\"~s\"}", [RefreshToken])),
    request(post, "/tokens/refresh", Body, 200).

%% @doc Отзывает один токен по его `jti' (`DELETE /tokens/{jti}').
%%
%% Идемпотентно: отзыв несуществующего `jti' — тоже успех.
%%
%% @param Jti Идентификатор токена из claim `jti'.
%% @returns `{ok, _}' либо `{error, 500}' — хранилище недоступно, отзыв НЕ
%%          выполнен, попытку следует повторить.
-spec revoke_token(string()) -> {ok, binary()} | {error, term()}.
revoke_token(Jti) ->
    request(delete, "/tokens/" ++ Jti, <<>>, 204).

%% @doc Отзывает все активные токены субъекта.
%%
%% Ручка `DELETE /subjects/{sub}/tokens'. Нужна при компрометации: гасить токены
%% по одному нельзя, их `jti' вызывающему неизвестны.
%%
%% @param Sub Субъект, чьи токены гасятся.
%% @returns `{ok, Body}' с полем `revoked'; истёкшие токены не считаются.
-spec revoke_subject(string()) -> {ok, binary()} | {error, term()}.
revoke_subject(Sub) ->
    request(delete, "/subjects/" ++ Sub ++ "/tokens", <<>>, 200).

%% @private Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.
-spec request(atom(), string(), binary(), integer()) -> {ok, binary()} | {error, term()}.
request(Method, Path, Body, Expected) ->
    application:ensure_all_started(inets),
    Service = case os:getenv("JWT_SERVICE_URL") of
        false -> "http://localhost:8080";
        Value -> Value
    end,

    %% Код считается здесь, а не переиспользуется: один код — один запрос.
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

%% @doc Демонстрирует полный жизненный цикл токена.
-spec main() -> ok.
main() ->
    {ok, Issued} = issue_token("svc-a", "svc-b", true),
    io:format("выпущен: ~s~n", [Issued]),

    %% В боевом коде разберите JSON библиотекой (например, jsx) и достаньте
    %% refresh_token из ответа.
    {ok, Refreshed} = refresh_tokens("положите-сюда-refresh_token"),
    io:format("обновлён: ~s~n", [Refreshed]),

    {ok, Revoked} = revoke_subject("svc-a"),
    io:format("массовый отзыв: ~s~n", [Revoked]).
