#!/usr/bin/perl

=head1 NAME

jwt-service-client — клиент jwt-service-app для эндпоинтов уровня 3 (TOTP)

=head1 SYNOPSIS

    my $issued = issue_token('svc-a', 'svc-b', 1);
    my $refreshed = refresh_tokens($issued->{refresh_token});
    my $count = revoke_subject('svc-a');

=head1 DESCRIPTION

Покрывает все четыре ручки уровня 3: выпуск токена, обмен refresh-токена, отзыв
одного токена и массовый отзыв токенов субъекта.

Зависимости: C<Authen::OATH>, C<Convert::Base32>, C<LWP::UserAgent>, C<JSON::PP>.

=head2 Окружение

=over 4

=item C<AUTH_TOTP_SECRET>

Общий TOTP-секрет в base32 (обязательно).

=item C<JWT_SERVICE_URL>

Базовый URL сервиса, по умолчанию C<http://localhost:8080>.

=back

=head2 Один код — один запрос

Код считается B<заново перед каждым запросом>. При включённой на сервере защите
от переигрывания (C<AUTH_TOTP_REPLAY_PROTECTION>) повторное предъявление того же
кода вернёт C<401>, хотя сам код ещё не истёк.

=cut

use strict;
use warnings;

use Authen::OATH;
use Convert::Base32 qw(decode_base32);
use HTTP::Request;
use JSON::PP qw(encode_json decode_json);
use LWP::UserAgent;

# Значение claim iss. Должно совпадать при выпуске и проверке токена.
my $ISSUER_HOST = 'example.com';

my $SERVICE = $ENV{JWT_SERVICE_URL} // 'http://localhost:8080';

=head2 totp_code

    my $code = totp_code();

Вычисляет TOTP-код на текущий момент. Параметры соответствуют дефолтам сервиса:
SHA-1, 6 знаков, шаг 30 секунд.

Возвращает строку из шести десятичных знаков.

=cut

sub totp_code {
    my $secret = decode_base32($ENV{AUTH_TOTP_SECRET});
    return sprintf '%06d', Authen::OATH->new->totp($secret);
}

=head2 request

    my $response = request('POST', '/tokens', { sub => 'svc-a' });

Выполняет запрос к ручке уровня 3, подставляя свежий TOTP-код.

Параметры: HTTP-метод, путь ручки (начиная со слеша) и необязательная ссылка на
хеш с телом запроса.

Возвращает объект L<HTTP::Response>.

=cut

sub request {
    my ($method, $path, $body) = @_;

    my $req = HTTP::Request->new($method => "$SERVICE$path");

    # Код считается здесь, а не переиспользуется: один код — один запрос.
    $req->header('X-TOTP-Code'  => totp_code());
    $req->header('Host'         => $ISSUER_HOST);
    $req->header('Content-Type' => 'application/json');
    $req->content(encode_json($body)) if $body;

    return LWP::UserAgent->new->request($req);
}

=head2 issue_token

    my $issued = issue_token($sub, $aud, $with_refresh);

Выпускает access-токен (C<POST /tokens>).

Параметры: субъект (claim C<sub>), получатель (claim C<aud>) и признак того,
нужен ли refresh-токен для продления сессии.

Возвращает ссылку на хеш с полями C<token> и, если запрашивался,
C<refresh_token>.

Умирает при C<401> (неверный код), C<422> (некорректные параметры) и C<500>
(недоступны JWKS или Redis).

=cut

sub issue_token {
    my ($sub, $aud, $with_refresh) = @_;

    my $response = request('POST', '/tokens', {
        sub     => $sub,
        aud     => [$aud],
        refresh => $with_refresh ? JSON::PP::true : JSON::PP::false,
    });

    die 'выпуск не удался: ' . $response->code unless $response->code == 200;
    return decode_json($response->content);
}

=head2 refresh_tokens

    my $refreshed = refresh_tokens($refresh_token);

Обменивает refresh-токен на новую пару (C<POST /tokens/refresh>).

Старый токен после обмена недействителен: сохраните новый и выбросьте
предыдущий.

B<Внимание:> не повторяйте обмен старым токеном при потере ответа. Повторное
предъявление трактуется как кража и гасит всю семью — и refresh-токены, и
выданные по ним access-токены. Надёжнее выпустить пару заново.

Умирает при C<401>: токен неизвестен, истёк или уже использован.

=cut

sub refresh_tokens {
    my ($refresh_token) = @_;

    my $response = request('POST', '/tokens/refresh', {
        refresh_token => $refresh_token,
    });

    die 'обмен не удался: ' . $response->code unless $response->code == 200;
    return decode_json($response->content);
}

=head2 revoke_token

    revoke_token($jti);

Отзывает один токен по его C<jti> (C<DELETE /tokens/{jti}>).

Идемпотентно: отзыв несуществующего C<jti> — тоже успех.

Умирает при C<500>: хранилище недоступно и отзыв B<не выполнен> — попытку
следует повторить.

=cut

sub revoke_token {
    my ($jti) = @_;

    my $response = request('DELETE', "/tokens/$jti");
    die 'отзыв не удался: ' . $response->code unless $response->code == 204;
    return;
}

=head2 revoke_subject

    my $count = revoke_subject($sub);

Отзывает все активные токены субъекта (C<DELETE /subjects/{sub}/tokens>).

Нужен при компрометации: гасить токены по одному нельзя, их C<jti> вызывающему
неизвестны.

Возвращает число отозванных токенов; истёкшие не считаются.

=cut

sub revoke_subject {
    my ($sub) = @_;

    my $response = request('DELETE', "/subjects/$sub/tokens");
    die 'массовый отзыв не удался: ' . $response->code unless $response->code == 200;
    return decode_json($response->content)->{revoked};
}

# Демонстрация полного жизненного цикла токена.
my $issued = issue_token('svc-a', 'svc-b', 1);
printf "выпущен: %s...\n", substr($issued->{token}, 0, 32);

my $refreshed = refresh_tokens($issued->{refresh_token});
printf "обновлён: %s...\n", substr($refreshed->{token}, 0, 32);

printf "отозвано токенов: %d\n", revoke_subject('svc-a');
