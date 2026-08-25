#!/usr/bin/perl

=head1 NAME

jwt-service-client — jwt-service-app level 3 (TOTP) client

=head1 SYNOPSIS

    my $issued = issue_token('svc-a', 'svc-b', 1, { role => 'admin' });
    my $refreshed = refresh_tokens($issued->{refresh_token});
    my $count = revoke_subject('svc-a');

=head1 DESCRIPTION

Issue, refresh and revoke tokens over the four level 3 endpoints.

Dependencies: C<Authen::OATH>, C<Convert::Base32>, C<LWP::UserAgent>,
C<JSON::PP>.

Env: C<AUTH_TOTP_SECRET> (base32), C<JWT_SERVICE_URL> (default
C<http://localhost:8080>).

See README.md for endpoints, error codes and client rules.

=cut

use strict;
use warnings;

use Authen::OATH;
use Convert::Base32 qw(decode_base32);
use HTTP::Request;
use JSON::PP qw(encode_json decode_json);
use LWP::UserAgent;

# Sent as the Host header, becomes the iss claim.
my $ISSUER_HOST = 'example.com';

my $SERVICE = $ENV{JWT_SERVICE_URL} // 'http://localhost:8080';

=head2 totp_code

    my $code = totp_code();

Fresh TOTP code: SHA-1, 6 digits, 30-second step.

=cut

sub totp_code {
    my $secret = decode_base32($ENV{AUTH_TOTP_SECRET});
    return sprintf '%06d', Authen::OATH->new->totp($secret);
}

=head2 request

    my $response = request('POST', '/tokens', { sub => 'svc-a' });

Sends a level 3 request with a code computed right before the call. Takes the
HTTP method, the endpoint path and an optional body hashref; returns an
L<HTTP::Response>.

=cut

sub request {
    my ($method, $path, $body) = @_;

    my $req = HTTP::Request->new($method => "$SERVICE$path");

    $req->header('X-TOTP-Code'  => totp_code());
    $req->header('Host'         => $ISSUER_HOST);
    $req->header('Content-Type' => 'application/json');
    $req->content(encode_json($body)) if $body;

    return LWP::UserAgent->new->request($req);
}

=head2 issue_token

    my $issued = issue_token($sub, $aud, $with_refresh, { role => 'admin' });

C<POST /tokens>. Returns a hashref with C<token> and, if requested,
C<refresh_token>.

=cut

sub issue_token {
    my ($sub, $aud, $with_refresh, $claims) = @_;

    my $body = {
        sub     => $sub,
        aud     => [$aud],
        refresh => $with_refresh ? JSON::PP::true : JSON::PP::false,
    };
    $body->{claims} = $claims if $claims && %$claims;

    my $response = request('POST', '/tokens', $body);

    die 'issue failed: ' . $response->code unless $response->code == 200;
    return decode_json($response->content);
}

=head2 refresh_tokens

    my $refreshed = refresh_tokens($refresh_token);

C<POST /tokens/refresh> — returns a new pair; the old refresh token is dead once
the call succeeds.

=cut

sub refresh_tokens {
    my ($refresh_token) = @_;

    my $response = request('POST', '/tokens/refresh', {
        refresh_token => $refresh_token,
    });

    die 'refresh failed: ' . $response->code unless $response->code == 200;
    return decode_json($response->content);
}

=head2 revoke_token

    revoke_token($jti);

C<DELETE /tokens/{jti}> — idempotent.

=cut

sub revoke_token {
    my ($jti) = @_;

    my $response = request('DELETE', "/tokens/$jti");
    die 'revoke failed: ' . $response->code unless $response->code == 204;
    return;
}

=head2 revoke_subject

    my $count = revoke_subject($sub);

C<DELETE /subjects/{sub}/tokens> — returns the number of revoked tokens.

=cut

sub revoke_subject {
    my ($sub) = @_;

    my $response = request('DELETE', "/subjects/$sub/tokens");
    die 'bulk revoke failed: ' . $response->code unless $response->code == 200;
    return decode_json($response->content)->{revoked};
}

# Issue -> refresh -> revoke.
my $issued = issue_token('svc-a', 'svc-b', 1, { role => 'admin' });
printf "issued: %s...\n", substr($issued->{token}, 0, 32);

my $refreshed = refresh_tokens($issued->{refresh_token});
printf "refreshed: %s...\n", substr($refreshed->{token}, 0, 32);

printf "revoked: %d\n", revoke_subject('svc-a');
