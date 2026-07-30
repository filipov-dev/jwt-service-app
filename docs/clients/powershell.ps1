<#
.SYNOPSIS
    Клиент jwt-service-app для эндпоинтов уровня 3 (TOTP).

.DESCRIPTION
    Покрывает все четыре ручки: выпуск токена, обмен refresh-токена, отзыв одного
    токена и массовый отзыв токенов субъекта.

    TOTP считается через HMACSHA1 из .NET, дополнительных модулей не требуется.

    Переменные окружения:
    - AUTH_TOTP_SECRET — общий TOTP-секрет (см. примечание о base32);
    - JWT_SERVICE_URL  — базовый URL, по умолчанию http://localhost:8080.

    Пример трактует секрет как сырые байты (UTF-8); для совместимости с Google
    Authenticator добавьте декодер base32.

.NOTES
    Код считается ЗАНОВО перед каждым запросом. При включённой на сервере защите
    от переигрывания (AUTH_TOTP_REPLAY_PROTECTION) повторное предъявление того же
    кода вернёт 401, хотя сам код ещё не истёк.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Значение claim iss. Должно совпадать при выпуске и проверке токена.
$script:IssuerHost = 'example.com'
$script:Service = if ($env:JWT_SERVICE_URL) { $env:JWT_SERVICE_URL } else { 'http://localhost:8080' }

function Get-TotpCode {
    <#
    .SYNOPSIS
        Вычисляет TOTP-код на текущий момент.

    .DESCRIPTION
        Параметры соответствуют дефолтам сервиса: SHA-1, 6 знаков, шаг 30 секунд.
        Усечение — по RFC 4226 §5.3.

    .OUTPUTS
        System.String. Код из шести десятичных знаков.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $secret = [Text.Encoding]::UTF8.GetBytes($env:AUTH_TOTP_SECRET)
    $counter = [long][Math]::Floor(([DateTimeOffset]::UtcNow.ToUnixTimeSeconds()) / 30)

    $message = [BitConverter]::GetBytes($counter)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($message) }

    $hmac = [Security.Cryptography.HMACSHA1]::new($secret)
    $digest = $hmac.ComputeHash($message)

    $offset = $digest[$digest.Length - 1] -band 0x0f
    $code = (($digest[$offset] -band 0x7f) -shl 24) -bor
            ($digest[$offset + 1] -shl 16) -bor
            ($digest[$offset + 2] -shl 8) -bor
            $digest[$offset + 3]

    return '{0:D6}' -f ($code % 1000000)
}

function Invoke-LevelThreeRequest {
    <#
    .SYNOPSIS
        Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.

    .PARAMETER Method
        HTTP-метод.

    .PARAMETER Path
        Путь ручки, начиная со слеша.

    .PARAMETER Body
        Хеш-таблица с телом запроса либо $null, если тела нет.

    .OUTPUTS
        Разобранный ответ сервиса.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Body
    )

    $headers = @{
        # Код считается здесь, а не переиспользуется: один код — один запрос.
        'X-TOTP-Code' = Get-TotpCode
        'Host'        = $script:IssuerHost
    }

    $arguments = @{
        Method  = $Method
        Uri     = "$($script:Service)$Path"
        Headers = $headers
    }

    if ($Body) {
        $arguments.ContentType = 'application/json'
        $arguments.Body = ($Body | ConvertTo-Json -Compress)
    }

    return Invoke-RestMethod @arguments
}

function New-ServiceToken {
    <#
    .SYNOPSIS
        Выпускает access-токен (POST /tokens).

    .PARAMETER Subject
        Субъект, которому выдаётся токен (claim sub).

    .PARAMETER Audience
        Список получателей (claim aud); не должен быть пустым.

    .PARAMETER WithRefresh
        Запросить refresh-токен для продления сессии.

    .OUTPUTS
        Объект с полями token и, если запрашивался, refresh_token.

    .NOTES
        Ошибки: 401 — неверный TOTP-код, 422 — некорректные параметры,
        500 — недоступны JWKS или Redis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string[]]$Audience,
        [switch]$WithRefresh
    )

    return Invoke-LevelThreeRequest -Method 'POST' -Path '/tokens' -Body @{
        sub     = $Subject
        aud     = $Audience
        refresh = [bool]$WithRefresh
    }
}

function Update-ServiceToken {
    <#
    .SYNOPSIS
        Обменивает refresh-токен на новую пару (POST /tokens/refresh).

    .DESCRIPTION
        Старый токен после обмена недействителен: сохраните новый и выбросьте
        предыдущий.

    .PARAMETER RefreshToken
        Токен, полученный при выпуске или прошлом обмене.

    .OUTPUTS
        Объект с новой парой token и refresh_token.

    .NOTES
        ВНИМАНИЕ: не повторяйте обмен старым токеном при потере ответа. Повторное
        предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
        выданные по ним access-токены. Надёжнее выпустить пару заново.

        Ошибка 401 означает, что токен неизвестен, истёк или уже использован.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$RefreshToken)

    return Invoke-LevelThreeRequest -Method 'POST' -Path '/tokens/refresh' -Body @{
        refresh_token = $RefreshToken
    }
}

function Remove-ServiceToken {
    <#
    .SYNOPSIS
        Отзывает один токен по его jti (DELETE /tokens/{jti}).

    .DESCRIPTION
        Идемпотентно: отзыв несуществующего jti — тоже успех.

    .PARAMETER Jti
        Идентификатор токена из claim jti.

    .NOTES
        Ошибка 500 означает, что хранилище недоступно и отзыв НЕ выполнен:
        попытку следует повторить.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Jti)

    Invoke-LevelThreeRequest -Method 'DELETE' -Path "/tokens/$Jti" | Out-Null
}

function Remove-SubjectTokens {
    <#
    .SYNOPSIS
        Отзывает все активные токены субъекта.

    .DESCRIPTION
        Ручка DELETE /subjects/{sub}/tokens. Нужна при компрометации: гасить
        токены по одному нельзя, их jti вызывающему неизвестны.

    .PARAMETER Subject
        Субъект, чьи токены гасятся.

    .OUTPUTS
        System.Int32. Число отозванных токенов; истёкшие не считаются.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Subject)

    $response = Invoke-LevelThreeRequest -Method 'DELETE' -Path "/subjects/$Subject/tokens"
    return $response.revoked
}

# Демонстрация полного жизненного цикла токена.
$issued = New-ServiceToken -Subject 'svc-a' -Audience 'svc-b' -WithRefresh
Write-Host "выпущен: $($issued.token.Substring(0, 32))..."

$refreshed = Update-ServiceToken -RefreshToken $issued.refresh_token
Write-Host "обновлён: $($refreshed.token.Substring(0, 32))..."

Write-Host "отозвано токенов: $(Remove-SubjectTokens -Subject 'svc-a')"
