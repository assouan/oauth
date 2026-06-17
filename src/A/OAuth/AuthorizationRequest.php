<?php

declare(strict_types=1);

namespace A\OAuth;

use A\Serializable;
use A\SerializableTrait;

class AuthorizationRequest implements Serializable
{
    use SerializableTrait;

    public function __construct(
        protected(set) string $url,
        protected(set) string $verifier,
        protected(set) string $challenge,
        protected(set) string $redirect_uri,
        protected(set) int|string $client_id,
        protected(set) int $created_at,
    )
    {
    }

    public function to_array() : array
    {
        return [
            'url' => $this->url,
            'verifier' => $this->verifier,
            'challenge' => $this->challenge,
            'redirect_uri' => $this->redirect_uri,
            'client_id' => $this->client_id,
            'created_at' => $this->created_at,
        ];
    }

    public static function from_array(array $data) : static
    {
        return new static(
            (string)$data['url'],
            (string)$data['verifier'],
            (string)$data['challenge'],
            (string)$data['redirect_uri'],
            is_int($data['client_id']) ? $data['client_id'] : (string)$data['client_id'],
            (int)$data['created_at'],
        );
    }
}
