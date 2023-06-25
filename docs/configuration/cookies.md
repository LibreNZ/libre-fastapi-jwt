These are only applicable if `authjwt_token_location` is use cookies.

`authjwt_access_cookie_key`
:   The key of the cookie that holds the access token. Defaults to `__Host-access_token`

`authjwt_refresh_cookie_key`
:   The key of the cookie that holds the refresh token. Defaults to `__Host-refresh_token`

`authjwt_access_cookie_path`
:   What path should be set for the access cookie. Defaults to `'/'`, which will cause this
    access cookie to be sent in every request.

`authjwt_refresh_cookie_path`
:   What path should be set for the refresh cookie. Defaults to `'/'`, which will cause this
    refresh cookie to be sent in every request. 

`authjwt_cookie_max_age`
:   If set to `None` the cookie will expire when the browser is closed. Defaults to
    `86400` (24 hours). Expects seconds as `int`.

`authjwt_cookie_domain`
:   The domain can be used to specify a domain and subdomain for your cookies.
    Defaults to `None` which sets this cookie to only be readable by the domain that set it. 

`authjwt_cookie_secure`
:   If the secure flag is `True` cookie can only be transmitted securely over HTTPS,
    and it will not be sent over unencrypted HTTP connections. Defaults to `True`.

`authjwt_cookie_samesite`
:   The browser sends the cookie with both cross-site and same-site requests.
    Set to `'lax'` in production to improve protection for CSRF attacks. Defaults to `lax`.
    Read about this setting [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie#samesitesamesite-value)
