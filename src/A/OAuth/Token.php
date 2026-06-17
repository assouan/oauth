<?php

declare(strict_types=1);

namespace A\OAuth;

use A\Serializable;
use A\SerializableTrait;

class Token implements Serializable
{
    use SerializableTrait;

    public function __construct(
        protected(set) ?string $token_type = null,
        protected(set) ?string $access_token = null,
        protected(set) ?string $refresh_token = null,
        protected(set) ?int $expires_in = null,
        protected(set) ?string $expires_datetime = null,
    )
    {
    }

    public static function from_array(array $data) : static
    {
        $expires_in = $data['expires_in'] ?? $data['expiresIn'] ?? null;
        $expires_in = $expires_in === null || $expires_in === '' ? null : (int)$expires_in;
        $expires_datetime = $data['expires_datetime'] ?? null;

        if ($expires_datetime === null)
        {
            $expires_at = $data['expires_at'] ?? $data['expiresAt'] ?? $data['exp'] ?? $data['expiration'] ?? null;

            if ($expires_at !== null and $expires_at !== '')
            {
                $timestamp = is_numeric($expires_at) ? (int)$expires_at : strtotime((string)$expires_at);

                if ($timestamp !== false)
                {
                    $expires_datetime = date(DATE_ATOM, $timestamp);
                }
            }
            else if ($expires_in !== null)
            {
                $expires_datetime = date(DATE_ATOM, time() + $expires_in);
            }
        }

        return new static(
            token_type: self::string($data['token_type'] ?? $data['tokenType'] ?? null),
            access_token: self::string($data['access_token'] ?? $data['key'] ?? $data['api_key'] ?? null),
            refresh_token: self::string($data['refresh_token'] ?? $data['refreshToken'] ?? null),
            expires_in: $expires_in,
            expires_datetime: self::string($expires_datetime),
        );
    }

    public function to_array() : array
    {
        return [
            'token_type' => $this->token_type,
            'access_token' => $this->access_token,
            'refresh_token' => $this->refresh_token,
            'expires_in' => $this->expires_in,
            'expires_datetime' => $this->expires_datetime,
        ];
    }

    protected static function string(mixed $value) : ?string
    {
        if ($value === null)
        {
            return null;
        }

        $value = trim((string)$value);

        return $value === '' ? null : $value;
    }
}
