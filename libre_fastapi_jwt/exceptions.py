class AuthJWTException(Exception):
    """
    Base except which all libre_fastapi_jwt errors extend
    """

    pass


class InvalidHeaderError(AuthJWTException):
    """
    An error getting jwt in header or jwt header information from a request
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class JWTDecodeError(AuthJWTException):
    """
    An error decoding a JWT
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class CSRFError(AuthJWTException):
    """
    An error with CSRF protection
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class MissingTokenError(AuthJWTException):
    """
    Error raised when token not found
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class RevokedTokenError(AuthJWTException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class AccessTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-access JWT attempt to access an endpoint
    protected by jwt_required, jwt_optional, fresh_jwt_required
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class RefreshTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-refresh JWT attempt to access an endpoint
    protected by jwt_refresh_token_required
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class FreshTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-fresh JWT attempt to access an endpoint
    protected by fresh_jwt_required
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class ExpiredSignatureError(AuthJWTException):
    """
    Error raised when a valid access token expired
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class NotEnoughPermissions(AuthJWTException):
    """
    Error raised when a valid JWT attempt to access an endpoint
    protected by scope requirements
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class ClaimsRequired(AuthJWTException):
    """
    Error raised when a valid JWT attempt to acces and endpoint
    that needs mandatory claims
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message