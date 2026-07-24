<?php
// PHP — библиотека: spomky-labs/otphp (`composer require spomky-labs/otphp`)
require 'vendor/autoload.php';

use OTPHP\TOTP;

$secret = getenv('AUTH_TOTP_SECRET');                         // base32
$service = getenv('JWT_SERVICE_URL') ?: 'http://localhost:8080';

$code = TOTP::createFromSecret($secret)->now();               // SHA-1, 6, 30с

$ch = curl_init("$service/tokens");
curl_setopt_array($ch, [
    CURLOPT_POST => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_HTTPHEADER => ["X-TOTP-Code: $code", "Host: example.com", "Content-Type: application/json"],
    CURLOPT_POSTFIELDS => '{"sub":"svc-a","aud":["svc-b"]}',
]);
echo curl_exec($ch), "\n";
