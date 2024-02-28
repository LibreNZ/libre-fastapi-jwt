from datetime import timedelta
from pydantic import field_validator, ConfigDict, BaseModel, validator, StrictBool, StrictInt, StrictStr, StrictBytes


class LoadConfig(BaseModel):
    authjwt_token_location: set[StrictStr] | None = {"headers"}
    authjwt_secret_key: StrictStr | StrictBytes | None = None
    authjwt_public_key: StrictStr | None = None
    authjwt_private_key: StrictStr | None = None
    authjwt_algorithm: StrictStr | None = "HS256"
    authjwt_decode_algorithms: list[StrictStr] | None = None
    authjwt_decode_leeway: StrictInt | timedelta | None = 0
    authjwt_encode_issuer: StrictStr | None = None
    authjwt_decode_issuer: StrictStr | None = None
    authjwt_decode_audience: StrictStr | set[StrictStr] | None = None
    authjwt_denylist_enabled: StrictBool | None = False
    authjwt_denylist_token_checks: set[StrictStr] | None = {"access", "refresh"}
    authjwt_header_name: StrictStr | None = "Authorization"
    authjwt_header_type: StrictStr | None = "Bearer"
    authjwt_access_token_expires: StrictBool | StrictInt | timedelta | None = timedelta(minutes=15)
    authjwt_refresh_token_expires: StrictBool | StrictInt | timedelta | None = timedelta(days=14)
    # option for create cookies
    authjwt_access_cookie_key: StrictStr | None = "access_token"
    authjwt_refresh_cookie_key: StrictStr | None = "refresh_token"
    authjwt_access_cookie_path: StrictStr | None = "/"
    authjwt_refresh_cookie_path: StrictStr | None = "/"
    authjwt_cookie_max_age: StrictInt | None = 86400
    authjwt_cookie_domain: StrictStr | None = None
    authjwt_cookie_secure: StrictBool | None = True
    authjwt_cookie_samesite: StrictStr | None = "lax"
    # option for double submit csrf protection
    authjwt_cookie_csrf_protect: StrictBool | None = True
    authjwt_access_csrf_cookie_key: StrictStr | None = "csrf_access"
    authjwt_refresh_csrf_cookie_key: StrictStr | None = "csrf_refresh"
    authjwt_access_csrf_cookie_path: StrictStr | None = "/"
    authjwt_refresh_csrf_cookie_path: StrictStr | None = "/"
    authjwt_access_csrf_header_name: StrictStr | None = "X-CSRF-Token"
    authjwt_refresh_csrf_header_name: StrictStr | None = "X-CSRF-Token"
    authjwt_csrf_methods: set[StrictStr] | None = {"POST", "PUT", "PATCH", "DELETE"}
    # options to adjust token's type claim
    authjwt_token_type_claim: StrictBool | None = True
    authjwt_access_token_type: StrictStr | None = "access"
    authjwt_refresh_token_type: StrictStr | None = "refresh"
    authjwt_token_type_claim_name: StrictStr | None = "type"

    @field_validator("authjwt_access_token_expires")
    @classmethod
    def validate_access_token_expires(cls, v):
        if v is True:
            raise ValueError("The 'authjwt_access_token_expires' only accept value False (bool)")
        return v

    @field_validator("authjwt_refresh_token_expires")
    @classmethod
    def validate_refresh_token_expires(cls, v):
        if v is True:
            raise ValueError("The 'authjwt_refresh_token_expires' only accept value False (bool)")
        return v

    @field_validator("authjwt_denylist_token_checks")
    def validate_denylist_token_checks(cls, v):
        if not all(item in ["access", "refresh"] for item in v):
            raise ValueError("The 'authjwt_denylist_token_checks' must be 'access' or 'refresh'")
        return v

    @field_validator("authjwt_token_location")
    def validate_token_location(cls, v):
        if not all(item in ["headers", "cookies"] for item in v):
            raise ValueError("The 'authjwt_token_location' must be 'headers', 'cookies' or both")
        return v

    @field_validator("authjwt_cookie_samesite")
    @classmethod
    def validate_cookie_samesite(cls, v):
        if v not in ["strict", "lax", "none"]:
            raise ValueError("The 'authjwt_cookie_samesite' must be 'strict', 'lax' or 'none'")
        return v

    @field_validator("authjwt_csrf_methods")
    def validate_csrf_methods(cls, v):
        if not all(item.upper() in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"} for item in v):
            raise ValueError("The 'authjwt_csrf_methods' must be a valid HTTP request method name")
        return {item.upper() for item in v}

    @field_validator("authjwt_token_type_claim_name")
    @classmethod
    def validate_token_type_claim_name(cls, v):
        if v.lower() in {"iss", "sub", "aud", "exp", "nbf", "iat", "jti"}:
            raise ValueError("The 'authjwt_token_type_claim_name' can not override default JWT claims")
        return v

    model_config = ConfigDict(str_min_length=1, str_strip_whitespace=True)
