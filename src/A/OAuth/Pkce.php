<?php

declare(strict_types=1);

namespace A\OAuth;

class Pkce
{
    public const MIN_VERIFIER_LENGTH = 43;

    public const MAX_VERIFIER_LENGTH = 128;

    protected const CODE_VERIFIER_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';

    public static function create_verifier(?int $length = null) : string
    {
        $length ??= random_int(self::MIN_VERIFIER_LENGTH, 127);

        if ($length < self::MIN_VERIFIER_LENGTH or $length > self::MAX_VERIFIER_LENGTH)
        {
            throw new \InvalidArgumentException('PKCE code verifier length must be between 43 and 128 characters.');
        }

        $last = strlen(self::CODE_VERIFIER_ALPHABET) - 1;
        $verifier = '';

        for ($i = 0; $i < $length; $i++)
        {
            $verifier .= self::CODE_VERIFIER_ALPHABET[random_int(0, $last)];
        }

        return $verifier;
    }

    public static function challenge_s256(string $verifier) : string
    {
        return self::base64_url(hash('sha256', $verifier, true));
    }

    public static function base64_url(string $bytes) : string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
