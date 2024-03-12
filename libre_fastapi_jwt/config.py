from datetime import timedelta
from typing import Optional, Union, Sequence, List
from pydantic import (
    BaseModel,
    StrictBool,
    StrictInt,
    StrictStr,
    StrictBytes,
    field_validator,
    ConfigDict
)

class LoadConfig(BaseModel):
    authjwt_token_location: Optional[Sequence[StrictStr]] = ['headers']
    authjwt_secret_key: Optional[Union[StrictStr,StrictBytes]] = None
    authjwt_public_key: Optional[StrictStr] = None
    authjwt_private_key: Optional[StrictStr] = None
    authjwt_algorithm: Optional[StrictStr] = "HS256"
    authjwt_decode_algorithms: Optional[List[StrictStr]] = None
    authjwt_decode_leeway: Optional[Union[StrictInt,timedelta]] = 0
    authjwt_encode_issuer: Optional[StrictStr] = None
    authjwt_decode_issuer: Optional[StrictStr] = None
    authjwt_decode_audience: Optional[Union[StrictStr,Sequence[StrictStr]]] = None
    authjwt_denylist_enabled: Optional[StrictBool] = False
    authjwt_denylist_token_checks: Optional[Sequence[StrictStr]] = ['access','refresh']
    authjwt_header_name: Optional[StrictStr] = "Authorization"
    authjwt_header_type: Optional[StrictStr] = "Bearer"
    authjwt_access_token_expires: Optional[Union[StrictBool,StrictInt,timedelta]] = timedelta(minutes=15)
    authjwt_refresh_token_expires: Optional[Union[StrictBool,StrictInt,timedelta]] = timedelta(days=14)
    # option for create cookies
    authjwt_access_cookie_key: Optional[StrictStr] = "__Host-access_token"
    authjwt_refresh_cookie_key: Optional[StrictStr] = "__Host-refresh_token"
    authjwt_access_cookie_path: Optional[StrictStr] = "/"
    authjwt_refresh_cookie_path: Optional[StrictStr] = "/"
    authjwt_cookie_max_age: Optional[StrictInt] = 86400
    authjwt_cookie_domain: Optional[StrictStr] = None
    authjwt_cookie_secure: Optional[StrictBool] = True
    authjwt_cookie_samesite: Optional[StrictStr] = "lax"
    # option for double submit csrf protection
    authjwt_cookie_csrf_protect: Optional[StrictBool] = True
    authjwt_access_csrf_cookie_key: Optional[StrictStr] = "csrf_access"
    authjwt_refresh_csrf_cookie_key: Optional[StrictStr] = "csrf_refresh"
    authjwt_access_csrf_cookie_path: Optional[StrictStr] = "/"
    authjwt_refresh_csrf_cookie_path: Optional[StrictStr] = "/"
    authjwt_access_csrf_header_name: Optional[StrictStr] = "X-CSRF-Token"
    authjwt_refresh_csrf_header_name: Optional[StrictStr] = "X-CSRF-Token"
    authjwt_csrf_methods: Optional[Sequence[StrictStr]] = ['POST','PUT','PATCH','DELETE']
    # options to adjust token's type claim
    authjwt_token_type_claim: Optional[StrictBool] = True
    authjwt_access_token_type: Optional[StrictStr] = "access"
    authjwt_refresh_token_type: Optional[StrictStr] = "refresh"
    authjwt_token_type_claim_name: Optional[StrictStr] = "type"

    @field_validator('authjwt_access_token_expires')
    def validate_access_token_expires(cls, v):
        if v is True:
            raise ValueError("The 'authjwt_access_token_expires' only accept value False (bool)")
        return v

    @field_validator('authjwt_refresh_token_expires')
    def validate_refresh_token_expires(cls, v):
        if v is True:
            raise ValueError("The 'authjwt_refresh_token_expires' only accept value False (bool)")
        return v

    @field_validator('authjwt_denylist_token_checks')
    def validate_denylist_token_checks(cls, v):
        if v is not None:
            if not all(item in ['access', 'refresh'] for item in v):
                raise ValueError("Each item in 'authjwt_denylist_token_checks' must be either 'access' or 'refresh'")
            return v

    @field_validator('authjwt_token_location')
    def validate_token_location(cls, v):
        if v is not None:
            if not all(item in ['headers', 'cookies'] for item in v):
                raise ValueError("Each item in 'authjwt_token_location' must be either 'headers' or 'cookies'")
            return v

    @field_validator('authjwt_cookie_samesite')
    def validate_cookie_samesite(cls, v):
        if v not in ['strict','lax','none']:
            raise ValueError("The 'authjwt_cookie_samesite' must be between 'strict', 'lax', 'none'")
        return v

    @field_validator('authjwt_csrf_methods')
    def validate_csrf_methods(cls, v):
        if v is not None:
            if not all(method.upper() in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"} for method in v):
                raise ValueError("The 'authjwt_csrf_methods' must be between http request methods")
            return [method.upper() for method in v]
        # if v.upper() not in {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH"}:
        #     raise ValueError("The 'authjwt_csrf_methods' must be between http request methods")
        # return v.upper()

    @field_validator('authjwt_token_type_claim_name')
    def validate_token_type_claim_name(cls, v):
        if v.lower() in {'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'}:
            raise ValueError("The 'authjwt_token_type_claim_name' can not override default JWT claims")
        return v

    model_config = ConfigDict(str_min_length=1, str_strip_whitespace=True)
