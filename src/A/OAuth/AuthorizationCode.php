<?php

declare(strict_types=1);

namespace A\OAuth;

class AuthorizationCode
{
    public static function authorization_url(string $endpoint, array $fields, bool $encode = true) : string
    {
        $separator = str_contains($endpoint, '?')
            ? (str_ends_with($endpoint, '?') || str_ends_with($endpoint, '&') ? '' : '&')
            : '?';

        return $endpoint . $separator . self::query($fields, $encode);
    }

    public static function token_fields(
        string $code,
        string $redirect_uri,
        int|string $client_id,
        ?string $code_verifier = null,
    ) : array
    {
        $fields = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $redirect_uri,
            'client_id' => $client_id,
        ];

        if ($code_verifier !== null and $code_verifier !== '')
        {
            $fields['code_verifier'] = $code_verifier;
        }

        return $fields;
    }

    protected static function query(array $fields, bool $encode) : string
    {
        if ($encode)
        {
            return http_build_query($fields, '', '&', PHP_QUERY_RFC3986);
        }

        $pairs = [];

        foreach ($fields as $key => $value)
        {
            if (is_bool($value))
            {
                $value = $value ? 'true' : 'false';
            }
            else if ($value === null)
            {
                $value = '';
            }

            $pairs[] = (string)$key . '=' . (string)$value;
        }

        return implode('&', $pairs);
    }
}
