<#
.SYNOPSIS
    jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

.DESCRIPTION
    TOTP is computed with .NET HMACSHA1, no extra modules needed.

    Env:
    - AUTH_TOTP_SECRET — shared TOTP secret (raw UTF-8 bytes here, see README.md);
    - JWT_SERVICE_URL  — service base URL, default http://localhost:8080.

.NOTES
    See README.md for endpoints, error codes and client rules.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Sent as the Host header, becomes the iss claim.
$script:IssuerHost = 'example.com'
$script:Service = if ($env:JWT_SERVICE_URL) { $env:JWT_SERVICE_URL } else { 'http://localhost:8080' }

function Get-TotpCode {
    <#
    .SYNOPSIS
        Fresh TOTP code: SHA-1, 6 digits, 30-second step.

    .DESCRIPTION
        Truncation follows RFC 4226 section 5.3.

    .OUTPUTS
        System.String. Six decimal digits.
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
        Sends a level 3 request with a code computed right before the call.

    .PARAMETER Method
        HTTP method.

    .PARAMETER Path
        Endpoint path.

    .PARAMETER Body
        Request body hashtable, or $null.

    .OUTPUTS
        The parsed service reply.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Method,
        [Parameter(Mandatory)][string]$Path,
        [hashtable]$Body
    )

    $headers = @{
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
        POST /tokens

    .PARAMETER Subject
        Subject.

    .PARAMETER Audience
        Audience.

    .PARAMETER WithRefresh
        Also ask for a refresh token.

    .PARAMETER Claims
        Hashtable of custom claims.

    .OUTPUTS
        Object with token and, if requested, refresh_token.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Subject,
        [Parameter(Mandatory)][string[]]$Audience,
        [switch]$WithRefresh,
        [hashtable]$Claims
    )

    $body = @{
        sub     = $Subject
        aud     = $Audience
        refresh = [bool]$WithRefresh
    }

    if ($Claims -and $Claims.Count -gt 0) { $body.claims = $Claims }

    return Invoke-LevelThreeRequest -Method 'POST' -Path '/tokens' -Body $body
}

function Update-ServiceToken {
    <#
    .SYNOPSIS
        POST /tokens/refresh

    .DESCRIPTION
        Returns a new pair; the old refresh token is dead once the call succeeds.

    .PARAMETER RefreshToken
        Token from an issue or a previous refresh.

    .OUTPUTS
        Object with the new token and refresh_token.
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
        DELETE /tokens/{jti}

    .DESCRIPTION
        Idempotent.

    .PARAMETER Jti
        Token id from the jti claim.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Jti)

    Invoke-LevelThreeRequest -Method 'DELETE' -Path "/tokens/$Jti" | Out-Null
}

function Remove-SubjectTokens {
    <#
    .SYNOPSIS
        DELETE /subjects/{sub}/tokens

    .PARAMETER Subject
        Subject whose tokens are revoked.

    .OUTPUTS
        System.Int32. Number of revoked tokens.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Subject)

    $response = Invoke-LevelThreeRequest -Method 'DELETE' -Path "/subjects/$Subject/tokens"
    return $response.revoked
}

# Issue -> refresh -> revoke.
$issued = New-ServiceToken -Subject 'svc-a' -Audience 'svc-b' -WithRefresh -Claims @{ role = 'admin' }
Write-Host "issued: $($issued.token.Substring(0, 32))..."

$refreshed = Update-ServiceToken -RefreshToken $issued.refresh_token
Write-Host "refreshed: $($refreshed.token.Substring(0, 32))..."

Write-Host "revoked: $(Remove-SubjectTokens -Subject 'svc-a')"
