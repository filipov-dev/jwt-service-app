<#
.SYNOPSIS
    jwt-service-app level 3 (TOTP) client: issue, refresh, revoke.

.DESCRIPTION
    Covers all four level 3 endpoints: issue a token, exchange a refresh token,
    revoke one token and revoke every token of a subject.

    TOTP is computed with .NET HMACSHA1, no extra modules needed.

    Environment:
    - AUTH_TOTP_SECRET — shared TOTP secret (see the base32 note below);
    - JWT_SERVICE_URL  — base URL, default http://localhost:8080.

    This example treats the secret as raw UTF-8 bytes; add a base32 decoder for
    Google Authenticator compatibility.

.NOTES
    The code is recomputed BEFORE EVERY REQUEST. With replay protection on
    (AUTH_TOTP_REPLAY_PROTECTION) the server rejects a code it has already seen
    with 401, even while that code is still inside its time window.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Sent as the Host header and becomes the iss claim. Must be the same on issue
# and on verify, or the token will not verify.
$script:IssuerHost = 'example.com'
$script:Service = if ($env:JWT_SERVICE_URL) { $env:JWT_SERVICE_URL } else { 'http://localhost:8080' }

function Get-TotpCode {
    <#
    .SYNOPSIS
        Computes a fresh TOTP code for right now.

    .DESCRIPTION
        Service defaults: SHA-1, 6 digits, 30-second step. Truncation follows
        RFC 4226 section 5.3.

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
        Sends a level 3 request.

    .DESCRIPTION
        The code is computed here rather than reused: one code, one request.

    .PARAMETER Method
        HTTP method.

    .PARAMETER Path
        Endpoint path.

    .PARAMETER Body
        Request body hashtable, or $null when there is none.

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
        Issues an access token (POST /tokens).

    .PARAMETER Subject
        Subject the token is issued to (sub claim).

    .PARAMETER Audience
        Audience (aud claim); must not be empty.

    .PARAMETER WithRefresh
        Also return a refresh token for extending the session.

    .PARAMETER Claims
        Hashtable of custom claims (role, scope, tenant): they sit next to the
        registered ones, so the consumer reads role, not extra.role. Reserved
        names (iss, sub, aud, exp, iat, nbf, jti) give 422 — change lifetime
        through ttl, not exp. Count and size are capped server-side.

    .OUTPUTS
        Object with token and, if requested, refresh_token.

    .NOTES
        Errors: 401 bad code, 422 bad parameters or forbidden claim, 500 JWKS or
        Redis unavailable.
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
        Exchanges a refresh token for a new pair (POST /tokens/refresh).

    .DESCRIPTION
        The old token dies on exchange: store the new one and drop the previous.

    .PARAMETER RefreshToken
        Token from an issue or a previous exchange.

    .OUTPUTS
        Object with the new token and refresh_token.

    .NOTES
        NEVER retry an exchange with the old token when the reply is lost. A
        second presentation reads as theft, and the server revokes the whole
        family — refresh tokens and the access tokens issued from them. Issue a
        new pair instead.

        401 means the token is unknown, expired or already used.
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
        Revokes one token by its jti (DELETE /tokens/{jti}).

    .DESCRIPTION
        Idempotent: revoking an unknown jti is success too.

    .PARAMETER Jti
        Token id from the jti claim.

    .NOTES
        500 means the store is unreachable and the token is NOT revoked: retry.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Jti)

    Invoke-LevelThreeRequest -Method 'DELETE' -Path "/tokens/$Jti" | Out-Null
}

function Remove-SubjectTokens {
    <#
    .SYNOPSIS
        Revokes every active token of a subject.

    .DESCRIPTION
        Endpoint DELETE /subjects/{sub}/tokens. The compromise path: tokens
        cannot be killed one by one because the caller does not know their jti.

    .PARAMETER Subject
        Subject whose tokens are killed.

    .OUTPUTS
        System.Int32. Number of revoked tokens; expired ones do not count.
    #>
    [CmdletBinding()]
    [OutputType([int])]
    param([Parameter(Mandatory)][string]$Subject)

    $response = Invoke-LevelThreeRequest -Method 'DELETE' -Path "/subjects/$Subject/tokens"
    return $response.revoked
}

# Full token lifecycle: issue, refresh, bulk revoke.
$issued = New-ServiceToken -Subject 'svc-a' -Audience 'svc-b' -WithRefresh -Claims @{ role = 'admin' }
Write-Host "issued: $($issued.token.Substring(0, 32))..."

$refreshed = Update-ServiceToken -RefreshToken $issued.refresh_token
Write-Host "refreshed: $($refreshed.token.Substring(0, 32))..."

Write-Host "revoked: $(Remove-SubjectTokens -Subject 'svc-a')"
