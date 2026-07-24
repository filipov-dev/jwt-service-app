#!/usr/bin/perl
# Perl — библиотека: Authen::OATH + Convert::Base32 + LWP::UserAgent
use strict; use warnings;
use Authen::OATH;
use Convert::Base32 qw(decode_base32);
use LWP::UserAgent;
use HTTP::Request;

my $secret  = decode_base32($ENV{AUTH_TOTP_SECRET});          # base32 -> bytes
my $service = $ENV{JWT_SERVICE_URL} // 'http://localhost:8080';

my $code = sprintf '%06d', Authen::OATH->new->totp($secret);  # SHA-1, 6, 30с

my $req = HTTP::Request->new(POST => "$service/tokens");
$req->header('X-TOTP-Code' => $code, 'Host' => 'example.com', 'Content-Type' => 'application/json');
$req->content('{"sub":"svc-a","aud":["svc-b"]}');

my $res = LWP::UserAgent->new->request($req);
print $res->code, "\n";
