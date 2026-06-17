# A\OAuth API contract

This package contains OAuth authorization-code helpers, PKCE utilities, token
response normalization, and a small client for exchanging authorization codes.

`Client` uses `assouan/http-sender` for HTTP requests and can receive an
optional `A\Proxy\ProxyConfig` from `assouan/http-proxy-socket`.
