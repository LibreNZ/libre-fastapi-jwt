class AuthJWTException(Exception):
    """
    Base except which all fastapi_jwt2 errors extend
    """

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


class InvalidHeaderError(AuthJWTException):
    """
    An error getting jwt in header or jwt header information from a request
    """


class JWTDecodeError(AuthJWTException):
    """
    An error decoding a JWT
    """


class CSRFError(AuthJWTException):
    """
    An error with CSRF protection
    """


class MissingTokenError(AuthJWTException):
    """
    Error raised when token not found
    """


class RevokedTokenError(AuthJWTException):
    """
    Error raised when a revoked token attempt to access a protected endpoint
    """


class AccessTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-access JWT attempt to access an endpoint
    protected by jwt_required, jwt_optional, fresh_jwt_required
    """


class RefreshTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-refresh JWT attempt to access an endpoint
    protected by jwt_refresh_token_required
    """


class FreshTokenRequired(AuthJWTException):
    """
    Error raised when a valid, non-fresh JWT attempt to access an endpoint
    protected by fresh_jwt_required
    """


class ExpiredSignatureError(AuthJWTException):
    """
    Error raised when a valid access token expired
    """


class NotEnoughPermissions(AuthJWTException):
    """
    Error raised when a valid JWT attempt to access an endpoint
    protected by scope requirements
    """


class ClaimsRequired(AuthJWTException):
    """
    Error raised when a valid JWT attempt to acces and endpoint
    that needs mandatory claims
    """
