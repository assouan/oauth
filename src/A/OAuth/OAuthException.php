<?php

declare(strict_types=1);

namespace A\OAuth;

class OAuthException extends \RuntimeException
{
    public function __construct(
        protected(set) int $status,
        protected(set) array $body,
        string $message,
    )
    {
        parent::__construct($message, $status);
    }
}
