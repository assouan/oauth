<?php

declare(strict_types=1);

namespace A\OAuth;

use A\Http\CurlClient;
use A\Http\Response;
use A\Proxy\ProxyConfig;

class Client
{
    public function __construct(
        protected(set) array $curl_options = [],
        protected(set) string $auth_base_url = '',
        protected(set) array $headers = [],
    )
    {
    }

    public function create_request(
        string $authorization_path,
        string $redirect_uri,
        int|string $client_id,
        array $fields = [],
        ?string $verifier = null,
        bool $encode = true,
    ) : AuthorizationRequest
    {
        $verifier ??= Pkce::create_verifier();
        $challenge = Pkce::challenge_s256($verifier);
        $url = AuthorizationCode::authorization_url($this->url($authorization_path), [
            'code_challenge' => $challenge,
            'redirect_uri' => $redirect_uri,
            'client_id' => $client_id,
            ...$fields,
        ], $encode);

        return new AuthorizationRequest($url, $verifier, $challenge, $redirect_uri, $client_id, time());
    }

    public function exchange_code(
        AuthorizationRequest $request,
        string $code,
        ?ProxyConfig $proxy = null,
        string $token_path = 'token',
    ) : Token
    {
        $body = [];
        $status = 0;

        for ($attempt = 0; $attempt < 2; $attempt++)
        {
            $client = new CurlClient($this->curl_options, $proxy, $this->headers);

            try
            {
                $response = $client->request(
                    'POST',
                    $this->url($token_path),
                    ['Content-Type' => 'application/x-www-form-urlencoded'],
                    http_build_query(AuthorizationCode::token_fields(
                        code: $code,
                        redirect_uri: $request->redirect_uri,
                        client_id: $request->client_id,
                        code_verifier: $request->verifier,
                    ), '', '&', PHP_QUERY_RFC3986),
                )->await();
            }
            finally
            {
                $client->close();
            }

            if (!$response instanceof Response)
            {
                throw new \RuntimeException('OAuth token request did not return an HTTP response.');
            }

            $status = $response->status;
            $body = json_decode($response->body, true);
            $body = is_array($body) ? $body : ['raw' => $response->body];

            if ($response->ok)
            {
                break;
            }

            $message = (string)($body['message'] ?? $body['error_description'] ?? $body['error'] ?? $response->reason);

            if ($attempt === 0 and str_contains($message, 'AnkamaAuthorizationNotFound'))
            {
                asleep(2.0);
                continue;
            }

            throw new OAuthException($response->status, $body, "OAuth token request failed with HTTP {$response->status}: {$message}");
        }

        $token = Token::from_array($body);

        if ($token->access_token === null)
        {
            throw new OAuthException($status, $body, 'OAuth token response did not contain an access token.');
        }

        return $token;
    }

    public function url(string $path) : string
    {
        return rtrim($this->auth_base_url, '/') . '/' . ltrim($path, '/');
    }
}
