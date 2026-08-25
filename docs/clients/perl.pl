#!/usr/bin/perl

=head1 NAME

jwt-service-client — jwt-service-app level 3 (TOTP) client

=head1 SYNOPSIS

    my $issued = issue_token('svc-a', 'svc-b', 1, { role => 'admin' });
    my $refreshed = refresh_tokens($issued->{refresh_token});
    my $count = revoke_subject('svc-a');

=head1 DESCRIPTION

Covers all four level 3 endpoints: issue a token, exchange a refresh token,
revoke one token and revoke every token of a subject.

Dependencies: C<Authen::OATH>, C<Convert::Base32>, C<LWP::UserAgent>, C<JSON::PP>.

=head2 Environment

=over 4

=item C<AUTH_TOTP_SECRET>

Shared TOTP secret, base32 (required).

=item C<JWT_SERVICE_URL>

Service base URL, default C<http://localhost:8080>.

=back

=head2 One code, one request

The code is recomputed B<before every request>. With replay protection on
(C<AUTH_TOTP_REPLAY_PROTECTION>) the server rejects a code it has already seen
with C<401>, even while that code is still inside its time window.

=cut

use strict;
use warnings;

use Authen::OATH;
use Convert::Base32 qw(decode_base32);
use HTTP::Request;
use JSON::PP qw(encode_json decode_json);
use LWP::UserAgent;

# Sent as the Host header and becomes the iss claim. Must be the same on issue
# and on verify, or the token will not verify.
my $ISSUER_HOST = 'example.com';

my $SERVICE = $ENV{JWT_SERVICE_URL} // 'http://localhost:8080';

=head2 totp_code

    my $code = totp_code();

Computes a fresh TOTP code for right now. Service defaults: SHA-1, 6 digits,
30-second step.

Returns six decimal digits.

=cut

sub totp_code {
    my $secret = decode_base32($ENV{AUTH_TOTP_SECRET});
    return sprintf '%06d', Authen::OATH->new->totp($secret);
}

=head2 request

    my $response = request('POST', '/tokens', { sub => 'svc-a' });

Sends a level 3 request. Takes the HTTP method, the endpoint path and an
optional body hashref.

Returns an L<HTTP::Response>.

=cut

sub request {
    my ($method, $path, $body) = @_;

    my $req = HTTP::Request->new($method => "$SERVICE$path");

    # Computed here rather than reused: one code, one request.
    $req->header('X-TOTP-Code'  => totp_code());
    $req->header('Host'         => $ISSUER_HOST);
    $req->header('Content-Type' => 'application/json');
    $req->content(encode_json($body)) if $body;

    return LWP::UserAgent->new->request($req);
}

=head2 issue_token

    my $issued = issue_token($sub, $aud, $with_refresh, { role => 'admin' });

Issues an access token (C<POST /tokens>).

Takes the subject (C<sub> claim), the audience (C<aud> claim), whether a refresh
token is wanted for extending the session, and an optional hashref of custom
claims.

Custom claims sit next to the registered ones, so the consumer reads C<role>,
not C<extra.role>. Reserved names (C<iss>, C<sub>, C<aud>, C<exp>, C<iat>,
C<nbf>, C<jti>) give C<422> — change lifetime through C<ttl>, not C<exp>. Count
and size are capped server-side.

Returns a hashref with C<token> and, if requested, C<refresh_token>.

Dies on C<401> (bad code), C<422> (bad parameters or forbidden claim) and
C<500> (JWKS or Redis unavailable).

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

Exchanges a refresh token for a new pair (C<POST /tokens/refresh>).

The old token dies on exchange: store the new one and drop the previous.

B<Never retry> an exchange with the old token when the reply is lost. A second
presentation reads as theft, and the server revokes the whole family — refresh
tokens and the access tokens issued from them. Issue a new pair instead.

Dies on C<401>: the token is unknown, expired or already used.

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

Revokes one token by its C<jti> (C<DELETE /tokens/{jti}>).

Idempotent: revoking an unknown C<jti> is success too.

Dies on C<500>: the store is unreachable and the token is B<not> revoked —
retry.

=cut

sub revoke_token {
    my ($jti) = @_;

    my $response = request('DELETE', "/tokens/$jti");
    die 'revoke failed: ' . $response->code unless $response->code == 204;
    return;
}

=head2 revoke_subject

    my $count = revoke_subject($sub);

Revokes every active token of a subject (C<DELETE /subjects/{sub}/tokens>).

The compromise path: tokens cannot be killed one by one because the caller does
not know their C<jti>.

Returns the number of revoked tokens; expired ones do not count.

=cut

sub revoke_subject {
    my ($sub) = @_;

    my $response = request('DELETE', "/subjects/$sub/tokens");
    die 'bulk revoke failed: ' . $response->code unless $response->code == 200;
    return decode_json($response->content)->{revoked};
}

# Full token lifecycle: issue, refresh, bulk revoke.
my $issued = issue_token('svc-a', 'svc-b', 1, { role => 'admin' });
printf "issued: %s...\n", substr($issued->{token}, 0, 32);

my $refreshed = refresh_tokens($issued->{refresh_token});
printf "refreshed: %s...\n", substr($refreshed->{token}, 0, 32);

printf "revoked: %d\n", revoke_subject('svc-a');
