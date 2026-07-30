' Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).
'
' TOTP считается через HMACSHA1 из .NET, внешних пакетов не требуется.
'
' Окружение:
'   AUTH_TOTP_SECRET — общий TOTP-секрет (см. примечание о base32);
'   JWT_SERVICE_URL  — базовый URL, по умолчанию http://localhost:8080.
'
' Пример трактует секрет как сырые байты (UTF-8); для совместимости с Google
' Authenticator добавьте декодер base32.

Imports System
Imports System.Net.Http
Imports System.Security.Cryptography
Imports System.Text
Imports System.Text.Json

''' <summary>
''' Клиент сервиса выдачи токенов, покрывающий все четыре ручки уровня 3.
''' </summary>
''' <remarks>
''' TOTP-код считается <b>заново перед каждым запросом</b>. При включённой на
''' сервере защите от переигрывания (<c>AUTH_TOTP_REPLAY_PROTECTION</c>) повторное
''' предъявление того же кода вернёт <c>401</c>, хотя сам код ещё не истёк.
''' </remarks>
Public Class JwtServiceClient

    ''' <summary>Значение claim <c>iss</c>. Должно совпадать при выпуске и проверке.</summary>
    Private Const IssuerHost As String = "example.com"

    Private ReadOnly _baseUrl As String
    Private ReadOnly _secret As Byte()
    Private ReadOnly _http As New HttpClient()

    ''' <summary>Создаёт клиент.</summary>
    ''' <param name="baseUrl">Базовый URL сервиса.</param>
    ''' <param name="secret">Общий TOTP-секрет.</param>
    Public Sub New(baseUrl As String, secret As String)
        _baseUrl = baseUrl
        _secret = Encoding.UTF8.GetBytes(secret)
    End Sub

    ''' <summary>Собирает клиент из переменных окружения.</summary>
    ''' <returns>Готовый клиент.</returns>
    ''' <exception cref="InvalidOperationException">Не задан AUTH_TOTP_SECRET.</exception>
    Public Shared Function FromEnv() As JwtServiceClient
        Dim service = Environment.GetEnvironmentVariable("JWT_SERVICE_URL")
        If String.IsNullOrEmpty(service) Then service = "http://localhost:8080"

        Dim secret = Environment.GetEnvironmentVariable("AUTH_TOTP_SECRET")
        If String.IsNullOrEmpty(secret) Then
            Throw New InvalidOperationException("нужен AUTH_TOTP_SECRET")
        End If

        Return New JwtServiceClient(service, secret)
    End Function

    ''' <summary>Вычисляет TOTP-код на текущий момент.</summary>
    ''' <returns>Код из шести десятичных знаков.</returns>
    ''' <remarks>
    ''' Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
    ''' Усечение — по RFC 4226 §5.3.
    ''' </remarks>
    Private Function TotpCode() As String
        Dim counter As Long = DateTimeOffset.UtcNow.ToUnixTimeSeconds() \ 30

        Dim message = BitConverter.GetBytes(counter)
        If BitConverter.IsLittleEndian Then Array.Reverse(message)

        Using hmac As New HMACSHA1(_secret)
            Dim digest = hmac.ComputeHash(message)

            Dim offset As Integer = digest(digest.Length - 1) And &H0F
            Dim code As Integer =
                ((digest(offset) And &H7F) << 24) Or
                (digest(offset + 1) << 16) Or
                (digest(offset + 2) << 8) Or
                digest(offset + 3)

            Return (code Mod 1000000).ToString("D6")
        End Using
    End Function

    ''' <summary>Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.</summary>
    ''' <param name="method">HTTP-метод.</param>
    ''' <param name="path">Путь ручки, начиная со слеша.</param>
    ''' <param name="body">Тело запроса либо <c>Nothing</c>, если тела нет.</param>
    ''' <returns>Кортеж из HTTP-кода и тела ответа.</returns>
    Private Function Request(method As HttpMethod, path As String, body As String) _
        As (Status As Integer, Body As String)

        Using message As New HttpRequestMessage(method, _baseUrl & path)
            ' Код считается здесь, а не переиспользуется: один код — один запрос.
            message.Headers.Add("X-TOTP-Code", TotpCode())
            message.Headers.Host = IssuerHost

            If body IsNot Nothing Then
                message.Content = New StringContent(body, Encoding.UTF8, "application/json")
            End If

            Dim response = _http.Send(message)
            Return (CInt(response.StatusCode), response.Content.ReadAsStringAsync().Result)
        End Using
    End Function

    ''' <summary>Выпускает access-токен (<c>POST /tokens</c>).</summary>
    ''' <param name="subject">Субъект, которому выдаётся токен (claim <c>sub</c>).</param>
    ''' <param name="audience">Получатель (claim <c>aud</c>).</param>
    ''' <param name="withRefresh">Запросить refresh-токен для продления сессии.</param>
    ''' <returns>Тело ответа с полями <c>token</c> и, если запрашивался, <c>refresh_token</c>.</returns>
    ''' <exception cref="InvalidOperationException">
    ''' <c>401</c> — неверный код, <c>422</c> — параметры, <c>500</c> — JWKS или Redis.
    ''' </exception>
    Public Function IssueToken(subject As String, audience As String,
                               Optional withRefresh As Boolean = False) As String

        Dim body = $"{{""sub"":""{subject}"",""aud"":[""{audience}""],""refresh"":{withRefresh.ToString().ToLower()}}}"
        Dim result = Request(HttpMethod.Post, "/tokens", body)

        If result.Status <> 200 Then
            Throw New InvalidOperationException($"выпуск не удался: {result.Status}")
        End If

        Return result.Body
    End Function

    ''' <summary>Обменивает refresh-токен на новую пару (<c>POST /tokens/refresh</c>).</summary>
    ''' <param name="refreshToken">Токен из выпуска или прошлого обмена.</param>
    ''' <returns>Тело ответа с новой парой.</returns>
    ''' <remarks>
    ''' Старый токен после обмена недействителен: сохраните новый и выбросьте
    ''' предыдущий.
    ''' <para>
    ''' <b>Внимание:</b> не повторяйте обмен старым токеном при потере ответа.
    ''' Повторное предъявление трактуется как кража и гасит всю семью — и
    ''' refresh-токены, и выданные по ним access-токены. Надёжнее выпустить пару
    ''' заново.
    ''' </para>
    ''' </remarks>
    ''' <exception cref="InvalidOperationException">
    ''' <c>401</c> — токен неизвестен, истёк или уже использован.
    ''' </exception>
    Public Function RefreshTokens(refreshToken As String) As String
        Dim body = $"{{""refresh_token"":""{refreshToken}""}}"
        Dim result = Request(HttpMethod.Post, "/tokens/refresh", body)

        If result.Status <> 200 Then
            Throw New InvalidOperationException($"обмен не удался: {result.Status}")
        End If

        Return result.Body
    End Function

    ''' <summary>Отзывает один токен по его <c>jti</c> (<c>DELETE /tokens/{jti}</c>).</summary>
    ''' <param name="jti">Идентификатор токена из claim <c>jti</c>.</param>
    ''' <remarks>Идемпотентно: отзыв несуществующего <c>jti</c> — тоже успех.</remarks>
    ''' <exception cref="InvalidOperationException">
    ''' <c>500</c> — хранилище недоступно, отзыв НЕ выполнен: повторите попытку.
    ''' </exception>
    Public Sub RevokeToken(jti As String)
        Dim result = Request(HttpMethod.Delete, $"/tokens/{jti}", Nothing)

        If result.Status <> 204 Then
            Throw New InvalidOperationException($"отзыв не удался: {result.Status}")
        End If
    End Sub

    ''' <summary>Отзывает все активные токены субъекта.</summary>
    ''' <param name="subject">Субъект, чьи токены гасятся.</param>
    ''' <returns>Число отозванных токенов; истёкшие не считаются.</returns>
    ''' <remarks>
    ''' Ручка <c>DELETE /subjects/{sub}/tokens</c>. Нужна при компрометации: гасить
    ''' токены по одному нельзя, их <c>jti</c> вызывающему неизвестны.
    ''' </remarks>
    Public Function RevokeSubject(subject As String) As Integer
        Dim result = Request(HttpMethod.Delete, $"/subjects/{subject}/tokens", Nothing)

        If result.Status <> 200 Then
            Throw New InvalidOperationException($"массовый отзыв не удался: {result.Status}")
        End If

        Using document = JsonDocument.Parse(result.Body)
            Return document.RootElement.GetProperty("revoked").GetInt32()
        End Using
    End Function

End Class

''' <summary>Демонстрирует полный жизненный цикл токена.</summary>
Module Program
    ''' <summary>Точка входа.</summary>
    Sub Main()
        Dim client = JwtServiceClient.FromEnv()

        Dim issued = client.IssueToken("svc-a", "svc-b", withRefresh:=True)
        Console.WriteLine($"выпущен: {issued}")

        Using document = JsonDocument.Parse(issued)
            Dim refreshToken = document.RootElement.GetProperty("refresh_token").GetString()
            Console.WriteLine($"обновлён: {client.RefreshTokens(refreshToken)}")
        End Using

        Console.WriteLine($"отозвано токенов: {client.RevokeSubject("svc-a")}")
    End Sub
End Module
