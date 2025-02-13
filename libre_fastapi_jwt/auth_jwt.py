import logging

# Get the logger instance
logger = logging.getLogger(__name__)
import hmac
import re
from uuid import uuid4
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Sequence, Union

import jwt
from fastapi import Response, WebSocket, Header
from fastapi.requests import HTTPConnection
from fastapi.openapi.models import HTTPBearer as HTTPBearerModel
from fastapi.security.http import HTTPBase

from jwt.algorithms import has_crypto, requires_cryptography
from jwt.exceptions import ExpiredSignatureError

from libre_fastapi_jwt.auth_config import AuthConfig
from libre_fastapi_jwt.exceptions import (
    AccessTokenRequired,
    ClaimsRequired,
    CSRFError,
    FreshTokenRequired,
    InvalidHeaderError,
    JWTDecodeError,
    MissingTokenError,
    NotEnoughPermissions,
    RefreshTokenRequired,
    RevokedTokenError,
)


class AuthJWT(AuthConfig):
    def __init__(
        self,
        req: HTTPConnection = None,
        res: Response = None,
        token: str = Header(None),
    ):
        """
        Get jwt header from incoming request or get
        request and response object if jwt in the cookie

        :param req: all incoming request
        :param res: response from endpoint
        :param token: Bearer token to show in /docs
        """

        logger.debug("Initializing AuthJWT...")
        self._required_claims = []
        self._required_roles = []

        if token and req != None:
            logger.debug(f"Token: {token}")
            auth = (b"authorization", bytes("Bearer {}".format(token), "UTF-8"))
            logger.debug("Appending Bearer token to request header")
            req.headers._list.append(auth)
            logger.debug("Bearer token appended to request header")

        if res and self.jwt_in_cookies:
            logger.debug("Response object provided and JWT in cookies")
            self._response = res
            logger.debug("Response object stored")

        if req:
            logger.debug("Request object provided")
            # get request object when 'cookies' in authjwt_token_location
            if self.jwt_in_cookies:
                logger.debug("JWT in cookies, storing request object")
                self._request = req
                logger.debug("Request object stored")
            # get jwt in headers when 'headers' in authjwt_token_location
            if self.jwt_in_headers:
                logger.debug("JWT in headers, attempting to retrieve JWT from headers")
                auth = req.headers.get(self._header_name.lower())
                if auth:
                    logger.debug(f"JWT retrieved from header: {auth}")
                    self._get_jwt_from_headers(auth)
                    logger.debug("JWT retrieved from headers")
                else:
                    logger.debug("JWT not found in headers")

    def _get_jwt_from_headers(self, auth: str) -> "AuthJWT":
        """
        Get token from the headers

        :param auth: value from HeaderName
        """
        logger.debug("Get JWT from headers")
        header_name, header_type = self._header_name, self._header_type

        logger.debug(f"Header name: {header_name}, Header type: {header_type}")
        parts = auth.split()
        logger.debug(f"Authorization header parts: {parts}")

        # Make sure the header is in a valid format that we are expecting, ie
        if not header_type:
            logger.debug(
                "No header type specified, expecting format like: 'Bearer: <JWT>'"
            )
            # <HeaderName>: <JWT>
            if len(parts) != 1:
                msg = "Bad {} header. Expected value '<JWT>'".format(header_name)
                raise InvalidHeaderError(status_code=422, message=msg)
            self._token = parts[0]
            logger.debug(f"Token extracted: {self._token}")
        else:
            logger.debug(
                f"Header type specified, expected format would be: '{header_type} <JWT>'"
            )
            # <HeaderName>: <HeaderType> <JWT>
            if not re.match(r"{}\s".format(header_type), auth) or len(parts) != 2:
                msg = "Bad {} header. Expected value '{} <JWT>'".format(
                    header_name, header_type
                )
                logger.error(msg)
                raise InvalidHeaderError(status_code=422, message=msg)
            self._token = parts[1]
            logger.debug(f"Token extracted: {self._token}")

    def _get_jwt_identifier(self) -> str:
        logger.debug("Generating and returning JWT identifier (uuid)...")
        return str(uuid4())

    def _get_int_from_datetime(self, value: datetime) -> int:
        """
        :param value: datetime with or without timezone, if don't contains timezone
        it will managed as it is UTC
        :return: Seconds since the Epoch
        """
        if not isinstance(value, datetime):  # pragma: no cover
            logger.error("A datetime is required")
            raise TypeError("a datetime is required")
        return int(value.timestamp())

    def _get_secret_key(self, algorithm: str, process: str) -> str:
        """
        Get key with a different algorithm

        :param algorithm: algorithm for decode and encode token
        :param process: for indicating get key for encode or decode token

        :return: plain text or RSA depends on algorithm
        """
        logger.debug(
            f"Getting the secret key for JWT with algorithm: {algorithm} to perform an {process} action..."
        )
        symmetric_algorithms, asymmetric_algorithms = {
            "HS256",
            "HS384",
            "HS512",
        }, requires_cryptography

        if (
            algorithm not in symmetric_algorithms
            and algorithm not in asymmetric_algorithms
        ):
            raise ValueError("Algorithm {} could not be found".format(algorithm))

        if algorithm in symmetric_algorithms:
            logger.debug(f"Algorithm {algorithm} is a symmetric algorithm")
            if not self._secret_key:
                raise RuntimeError(
                    "authjwt_secret_key must be set when using symmetric algorithm {}".format(
                        algorithm
                    )
                )

            return self._secret_key

        if algorithm in asymmetric_algorithms and not has_crypto:
            logger.error("Missing dependencies for using asymmetric algorithms")
            raise RuntimeError(
                "Missing dependencies for using asymmetric algorithms. run 'pip install libre-fastapi-jwt[asymmetric]'"
            )

        if process == "encode":
            if not self._private_key:
                raise RuntimeError(
                    "authjwt_private_key must be set when using asymmetric algorithm {}".format(
                        algorithm
                    )
                )
            logger.debug("Returning private key for encoding")
            return self._private_key

        if process == "decode":
            if not self._public_key:
                raise RuntimeError(
                    "authjwt_public_key must be set when using asymmetric algorithm {}".format(
                        algorithm
                    )
                )
            logger.debug("Returning public key for decoding")
            return self._public_key

        return str(f"{process} failed")

    def get_public_key(self) -> tuple[str, str]:
        """
        Return the public key and its thumbprint
        
        :return: A tuple containing (public_key, thumbprint)
        :raises RuntimeError: If public key is not configured
        """
        logger.debug("Getting public key and its thumbprint...")
        
        if not self._public_key:
            raise RuntimeError(
                "authjwt_public_key must be set to use an asymmetric algorithm"
            )

        try:
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from cryptography.hazmat.backends import default_backend
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
            import base64

            # Load the public key
            if isinstance(self._public_key, str):
                public_key_bytes = self._public_key.encode('utf-8')
            else:
                public_key_bytes = self._public_key

            pub_key = load_pem_public_key(public_key_bytes, backend=default_backend())

            # Get the DER-encoded public key
            der_encoded = pub_key.public_bytes(
                encoding=Encoding.DER,
                format=PublicFormat.SubjectPublicKeyInfo
            )

            # Compute SHA-256 thumbprint
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(der_encoded)
            thumbprint = digest.finalize()

            # Base64 URL encode the thumbprint
            thumbprint_str = base64.urlsafe_b64encode(thumbprint).decode('utf-8').rstrip('=')

            return self._public_key, thumbprint_str

        except Exception as e:
            logger.error(f"Error generating thumbprint: {e}")
            raise RuntimeError("Failed to generate public key thumbprint") from e

    def _create_token(
        self,
        subject: str,
        type_token: str,
        exp_time: Optional[int],
        fresh: Optional[bool] = False,
        algorithm: Optional[str] = None,
        headers: Optional[Dict] = None,
        issuer: Optional[str] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict] = {},
    ) -> str:
        """
        Create token for access_token and refresh_token (utf-8)

        :param subject: Identifier for who this token is for example id or username from database.
        :param type_token: indicate token is access_token or refresh_token
        :param exp_time: Set the duration of the JWT
        :param fresh: Optional when token is access_token this param required
        :param algorithm: algorithm allowed to encode the token
        :param headers: valid dict for specifying additional headers in JWT header section
        :param issuer: expected issuer in the JWT
        :param audience: expected audience in the JWT
        :param user_claims: Custom claims to include in this token. This data must be dictionary

        :return: Encoded token
        """
        logger.debug("Creating token...")

        # Validation type data
        if not isinstance(subject, (str, int)):
            logger.error("Invalid subject type. Must be a string or integer.")
            raise TypeError("subject must be a string or integer")
        if not isinstance(fresh, bool):
            logger.error("Invalid fresh type. Must be a boolean.")
            raise TypeError("fresh must be a boolean")
        if audience and not isinstance(audience, (str, list, tuple, set, frozenset)):
            logger.error("Invalid audience type. Must be a string or sequence.")
            raise TypeError("audience must be a string or sequence")
        if algorithm and not isinstance(algorithm, str):
            logger.error("Invalid algorithm type. Must be a string.")
            raise TypeError("algorithm must be a string")
        if headers and not isinstance(headers, dict):
            logger.error("Invalid headers type. Must be a dict.")
            raise TypeError("headers must be a dict")
        if user_claims and not isinstance(user_claims, dict):
            logger.error("Invalid user_claims type. Must be a dictionary.")
            raise TypeError("user_claims must be a dictionary")

        logger.debug("All input parameters validated successfully.")

        # Data section
        reserved_claims = {
            "sub": subject,
            "iat": self._get_int_from_datetime(datetime.now(timezone.utc)),
            "nbf": self._get_int_from_datetime(datetime.now(timezone.utc)),
            "jti": self._get_jwt_identifier(),
        }
        logger.debug(f"Reserved claims: {reserved_claims}")

        token_types = {
            "access": self._access_token_type,
            "refresh": self._refresh_token_type,
        }
        logger.debug(f"Token types: {token_types}")

        if self._token_type_claim:
            custom_claims = {self._token_type_claim_name: token_types[type_token]}
        else:
            custom_claims = {}
        logger.debug(f"Custom claims: {custom_claims}")

        # for access_token only fresh needed
        if type_token == "access":
            custom_claims["fresh"] = fresh
        logger.debug(f"Custom claims after fresh check: {custom_claims}")

        # if cookie in token location and csrf protection enabled
        if self.jwt_in_cookies and self._cookie_csrf_protect:
            custom_claims["csrf"] = self._get_jwt_identifier()
        logger.debug(f"Custom claims after CSRF check: {custom_claims}")

        if exp_time:
            reserved_claims["exp"] = exp_time
        logger.debug(f"Reserved claims after exp_time check: {reserved_claims}")

        if issuer:
            reserved_claims["iss"] = issuer
        logger.debug(f"Reserved claims after issuer check: {reserved_claims}")

        if audience:
            reserved_claims["aud"] = audience
        logger.debug(f"Reserved claims after audience check: {reserved_claims}")

        # Add kid claim from public key thumbprint
        try:
            # Get thumbprint directly, ignoring the public key
            _, thumbprint = self.get_public_key()
            reserved_claims["kid"] = thumbprint
            logger.debug(f"Added kid claim from public key thumbprint: {thumbprint}")
        except RuntimeError as e:
            logger.warning(f"Could not obtain kid claim. Potentially because AuthJWT is not using asymmetric encryption. Error was: {e}")
            # Fallback to a default kid if public key is not available
            reserved_claims["kid"] = "whoamikidding"
            logger.debug("Defaulting kid claim")

        algorithm = algorithm or self._algorithm
        logger.debug(f"Algorithm to be used: {algorithm}")

        try:
            secret_key = self._get_secret_key(algorithm, "encode")
            logger.debug("Secret key retrieved successfully.")
        except Exception as e:
            logger.error(f"Error retrieving secret key: {e}")
            raise

        token = jwt.encode(
            {**reserved_claims, **custom_claims, **user_claims},
            secret_key,
            algorithm=algorithm,
            headers=headers,
        )
        logger.debug(f"Token created successfully: {token}")

        return token

    def _has_token_in_denylist_callback(self) -> bool:
        """
        Return True if token denylist callback set
        """
        return self._token_in_denylist_callback is not None

    def _check_token_is_revoked(
        self, raw_token: Dict[str, Union[str, int, bool]]
    ) -> None:
        """
        Ensure that AUTHJWT_DENYLIST_ENABLED is true and callback regulated, and then
        call function denylist callback with passing decode JWT, if true
        raise exception Token has been revoked
        """
        if not self._denylist_enabled:
            return

        if not self._has_token_in_denylist_callback():
            raise RuntimeError(
                "A token_in_denylist_callback must be provided via "
                "the '@AuthJWT.token_in_denylist_loader' if "
                "authjwt_denylist_enabled is 'True'"
            )

        if self._token_in_denylist_callback.__func__(raw_token):
            logger.error("Token has been revoked")
            raise RevokedTokenError(status_code=401, message="Token has been revoked")

    def _get_expired_time(
        self,
        type_token: str,
        expires_time: Optional[Union[timedelta, int, bool]] = None,
    ) -> Union[None, int]:
        """
        Dynamic token expired, if expires_time is False exp claim not created

        :param type_token: indicate token is access_token or refresh_token
        :param expires_time: duration expired jwt

        :return: duration exp claim jwt
        """
        logger.debug("Starting to get expired time for token")
        logger.debug(f"Type of token: {type_token}, Expires time: {expires_time}")

        # Validate the type of expires_time
        if expires_time and not isinstance(expires_time, (timedelta, int, bool)):
            logger.error("Invalid expires_time type. Must be timedelta, int, or bool.")
            raise TypeError("expires_time must be between timedelta, int, bool")
        logger.debug("expires_time type validated successfully")

        # Determine the expiration time based on the type of token
        if expires_time is not False:
            if type_token == "access":
                expires_time = expires_time or self._access_token_expires
                logger.debug(f"Access token expires time set to: {expires_time}")
            if type_token == "refresh":
                expires_time = expires_time or self._refresh_token_expires
                logger.debug(f"Refresh token expires time set to: {expires_time}")

        # Calculate the expiration time if it is not False
        if expires_time is not False:
            if isinstance(expires_time, bool):
                if type_token == "access":
                    expires_time = self._access_token_expires
                    logger.debug(f"Access token expires time set to: {expires_time}")
                if type_token == "refresh":
                    expires_time = self._refresh_token_expires
                    logger.debug(f"Refresh token expires time set to: {expires_time}")
            if isinstance(expires_time, timedelta):
                expires_time = int(expires_time.total_seconds())
                logger.debug(f"Expires time converted to seconds: {expires_time}")

            expiration_timestamp = (
                self._get_int_from_datetime(datetime.now(timezone.utc)) + expires_time
            )
            logger.debug(f"Expiration timestamp calculated: {expiration_timestamp}")
            return expiration_timestamp
        else:
            logger.debug("Expires time is False, returning None")
            return None

    def create_access_token(
        self,
        subject: str,
        fresh: Optional[bool] = False,
        algorithm: Optional[str] = None,
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta, int, bool]] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict] = {},
    ) -> str:
        """
        Create an access token with X minutes for expired time (default),
        info for param and return check to function create token

        :return: hash token
        """
        logger.debug("Creating access token")
        logger.debug(
            f"Subject: {subject}, Fresh: {fresh}, Algorithm: {algorithm}, Headers: {headers}, Expires time: {expires_time}, Audience: {audience}, User claims: {user_claims}"
        )

        exp_time = self._get_expired_time("access", expires_time)
        logger.debug(f"Calculated expiration time: {exp_time}")

        token = self._create_token(
            subject=subject,
            type_token="access",
            exp_time=exp_time,
            fresh=fresh,
            algorithm=algorithm,
            headers=headers,
            audience=audience,
            user_claims=user_claims,
            issuer=self._encode_issuer,
        )
        logger.debug(f"Access token created: {token}")
        return token

    def create_refresh_token(
        self,
        subject: str,
        algorithm: Optional[str] = None,
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta, int, bool]] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict] = {},
    ) -> str:
        """
        Create a refresh token with X days for expired time (default),
        info for param and return check to function create token

        :return: hash token
        """
        logger.debug("Creating refresh token")
        logger.debug(
            f"Subject: {subject}, Algorithm: {algorithm}, Headers: {headers}, Expires time: {expires_time}, Audience: {audience}, User claims: {user_claims}"
        )

        exp_time = self._get_expired_time("refresh", expires_time)
        logger.debug(f"Calculated expiration time: {exp_time}")

        token = self._create_token(
            subject=subject,
            type_token="refresh",
            exp_time=exp_time,
            algorithm=algorithm,
            headers=headers,
            audience=audience,
            user_claims=user_claims,
        )
        logger.debug(f"Refresh token created: {token}")
        return token

    def create_pair_token(
        self,
        subject: str,
        fresh: Optional[bool] = False,
        algorithm: Optional[str] = None,
        headers: Optional[Dict] = None,
        expires_time: Optional[Union[timedelta, int, bool]] = None,
        audience: Optional[Union[str, Sequence[str]]] = None,
        user_claims: Optional[Dict] = {},
    ) -> Dict[str, str]:
        """
        Create a pair of access and refresh tokens with X days for expired time (default),
        info for param and return check to function create token

        :return: dictionary with access and refresh tokens
        """
        logger.debug("Creating pair of tokens")
        logger.debug(
            f"Subject: {subject}, Fresh: {fresh}, Algorithm: {algorithm}, Headers: {headers}, Expires time: {expires_time}, Audience: {audience}, User claims: {user_claims}"
        )

        pair_identifier = {"aid": str(uuid4())}
        logger.debug(f"Generated pair identifier: {pair_identifier}")

        refresh = self._create_token(
            subject=subject,
            type_token="refresh",
            exp_time=self._get_expired_time("refresh", expires_time),
            algorithm=algorithm,
            headers=headers,
            audience=audience,
            user_claims=user_claims | pair_identifier,
        )
        logger.debug(f"Refresh token created: {refresh}")

        access = self._create_token(
            subject=subject,
            type_token="access",
            exp_time=self._get_expired_time("access", expires_time),
            fresh=fresh,
            algorithm=algorithm,
            headers=headers,
            audience=audience,
            user_claims=user_claims | pair_identifier,
            issuer=self._encode_issuer,
        )
        logger.debug(f"Access token created: {access}")

        tokens = {"access_token": access, "refresh_token": refresh}
        logger.debug(f"Pair of tokens created: {tokens}")
        return tokens

    def _get_csrf_token(self, encoded_token: str) -> str:
        """
        Returns the CSRF double submit token from an encoded JWT.

        :param encoded_token: The encoded JWT
        :return: The CSRF double submit token
        """
        logger.debug("Getting CSRF token from encoded JWT")
        return self._verified_token(encoded_token)["csrf"]

    def set_access_cookies(
        self,
        encoded_access_token: str,
        response: Optional[Response] = None,
        max_age: Optional[int] = None,
    ) -> None:
        """
        Configures the response to set access token in a cookie.
        this will also set the CSRF double submit values in a separate cookie

        :param encoded_access_token: The encoded access token to set in the cookies
        :param response: The FastAPI response object to set the access cookies in
        :param max_age: The max age of the cookie value should be the number of seconds (integer)
        """
        logger.debug("Setting access cookies")
        logger.debug(
            f"Encoded access token: {encoded_access_token}, Response: {response}, Max age: {max_age}"
        )

        if not self.jwt_in_cookies:
            logger.warning("JWT in cookies is not enabled")
            raise RuntimeWarning(
                "set_access_cookies() called without 'authjwt_token_location' configured to use cookies"
            )

        if max_age and not isinstance(max_age, int):
            logger.error("max_age must be an integer")
            raise TypeError("max_age must be a integer")
        if response and not isinstance(response, Response):
            logger.error("The response must be a FastAPI Response object")
            raise TypeError("The response must be an object response FastAPI")

        response = response or self._response
        logger.debug(f"Using response object: {response}")

        # Set the access JWT in the cookie
        logger.debug("Setting access JWT in the cookie")
        response.set_cookie(
            self._access_cookie_key,
            encoded_access_token,
            max_age=max_age or self._cookie_max_age,
            path=self._access_cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=True,
            samesite=self._cookie_samesite,
        )
        logger.debug("Access JWT cookie set")

        # If enabled, set the csrf double submit access cookie
        if self._cookie_csrf_protect:
            logger.debug(
                "CSRF protection is enabled, setting CSRF token in a separate cookie"
            )
            response.set_cookie(
                self._access_csrf_cookie_key,
                self._get_csrf_token(encoded_access_token),
                max_age=max_age or self._cookie_max_age,
                path=self._access_csrf_cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=False,
                samesite=self._cookie_samesite,
            )
            logger.debug("CSRF token cookie set")

    def set_refresh_cookies(
        self,
        encoded_refresh_token: str,
        response: Optional[Response] = None,
        max_age: Optional[int] = None,
    ) -> None:
        """
        Configures the response to set refresh token in a cookie.
        this will also set the CSRF double submit values in a separate cookie

        :param encoded_refresh_token: The encoded refresh token to set in the cookies
        :param response: The FastAPI response object to set the refresh cookies in
        :param max_age: The max age of the cookie value should be the number of seconds (integer)
        """
        logger.debug("Set refresh cookies...")
        logger.debug("encoded_refresh_token: %s", encoded_refresh_token)
        logger.debug("response: %s", response)
        logger.debug("max_age: %s", max_age)

        if not self.jwt_in_cookies:
            logger.warning("JWT in cookies is not enabled")
            raise RuntimeWarning(
                "set_refresh_cookies() called without 'authjwt_token_location' configured to use cookies"
            )
        if max_age and not isinstance(max_age, int):
            logger.error("max_age must be an integer")
            raise TypeError("max_age must be a integer")
        if response and not isinstance(response, Response):
            logger.error("The response must be an object response FastAPI")
            raise TypeError("The response must be an object response FastAPI")

        response = response or self._response
        logger.debug("Using response: %s", response)

        # Set the refresh JWT in the cookie
        logger.debug("Setting a refresh JWT in the cookie")
        response.set_cookie(
            self._refresh_cookie_key,
            encoded_refresh_token,
            max_age=max_age or self._cookie_max_age,
            path=self._refresh_cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=True,
            samesite=self._cookie_samesite,
        )

        # If enabled, set the csrf double submit refresh cookie
        if self._cookie_csrf_protect:
            logger.debug("Setting a CSRF double submit refresh cookie")
            response.set_cookie(
                self._refresh_csrf_cookie_key,
                self._get_csrf_token(encoded_refresh_token),
                max_age=max_age or self._cookie_max_age,
                path=self._refresh_csrf_cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=False,
                samesite=self._cookie_samesite,
            )
        logger.debug("Finished setting the refresh cookies")

    def set_pair_cookies(
        self,
        encoded_pair_token: str,
        response: Optional[Response] = None,
        max_age: Optional[int] = None,
    ) -> None:
        """
        Configures the response to set access AND refresh token in a cookie.
        this will also set the CSRF double submit values in a separate cookie

        :param encoded_pair_token: Both encoded tokens as returned from create_pair_token() to set in the cookies
        :param response: The FastAPI response object to set the access cookies in
        :param max_age: The max age of the cookie value should be the number of seconds (integer)
        """
        logger.debug("Entering set_pair_cookies")
        logger.debug("encoded_pair_token: %s", encoded_pair_token)
        logger.debug("response: %s", response)
        logger.debug("max_age: %s", max_age)

        if not self.jwt_in_cookies:
            logger.warning("JWT in cookies is not enabled")
            raise RuntimeWarning(
                "set_pair_cookies() called without 'authjwt_token_location' configured to use cookies"
            )
        if max_age and not isinstance(max_age, int):
            logger.error("max_age must be an integer")
            raise TypeError("max_age must be a integer")
        if response and not isinstance(response, Response):
            logger.error("The response must be an object response FastAPI")
            raise TypeError("The response must be an object response FastAPI")

        response = response or self._response
        logger.debug("Using response: %s", response)

        # Set the access JWT in the cookie
        logger.debug("Setting access JWT in the cookie")
        response.set_cookie(
            self._access_cookie_key,
            encoded_pair_token["access_token"],
            max_age=max_age or self._cookie_max_age,
            path=self._access_cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=True,
            samesite=self._cookie_samesite,
        )

        # If enabled, set the csrf double submit access cookie
        if self._cookie_csrf_protect:
            logger.debug("Setting CSRF double submit access cookie")
            response.set_cookie(
                self._access_csrf_cookie_key,
                self._get_csrf_token(encoded_pair_token["access_token"]),
                max_age=max_age or self._cookie_max_age,
                path=self._access_csrf_cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=False,
                samesite=self._cookie_samesite,
            )

        # Set the refresh JWT in the cookie
        logger.debug("Setting refresh JWT in the cookie")
        response.set_cookie(
            self._refresh_cookie_key,
            encoded_pair_token["refresh_token"],
            max_age=max_age or self._cookie_max_age,
            path=self._refresh_cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=True,
            samesite=self._cookie_samesite,
        )

        # If enabled, set the csrf double submit refresh cookie
        if self._cookie_csrf_protect:
            logger.debug("Setting CSRF double submit refresh cookie")
            response.set_cookie(
                self._refresh_csrf_cookie_key,
                self._get_csrf_token(encoded_pair_token["refresh_token"]),
                max_age=max_age or self._cookie_max_age,
                path=self._refresh_csrf_cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=False,
                samesite=self._cookie_samesite,
            )
        logger.debug("Finished setting a pair of cookies")

    def unset_jwt_cookies(self, response: Optional[Response] = None) -> None:
        """
        Unset (delete) all jwt tokens stored in a cookie

        :param response: The FastAPI response object to delete the JWT cookies in.
        """
        logger.debug("Unsetting JWT cookies")
        self.unset_access_cookies(response)
        self.unset_refresh_cookies(response)

    def unset_access_cookies(self, response: Optional[Response] = None) -> None:
        """
        Remove access token and access CSRF double submit from the response cookies

        :param response: The FastAPI response object to delete the access cookies in.
        """
        logger.debug("Unsetting access JWT and CSRF cookies")
        if not self.jwt_in_cookies:
            raise RuntimeWarning(
                "unset_access_cookies() called without 'authjwt_token_location' configured to use cookies"
            )

        if response and not isinstance(response, Response):
            raise TypeError("The response must be an object response FastAPI")

        response = response or self._response

        logger.debug("Deleting access token cookie")
        response.delete_cookie(
            self._access_cookie_key,
            path=self._access_cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=True,
            samesite=self._cookie_samesite,
        )

        if self._cookie_csrf_protect:
            logger.debug("Deleting access CSRF token cookie")
            response.delete_cookie(
                self._access_csrf_cookie_key,
                path=self._access_csrf_cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=True,
                samesite=self._cookie_samesite,
            )

    def unset_refresh_cookies(self, response: Optional[Response] = None) -> None:
        """
        Remove refresh token and refresh CSRF double submit from the response cookies

        :param response: The FastAPI response object to delete the refresh cookies in.
        """
        logger.debug("Unsetting refresh JWT and CSRF cookies")
        if not self.jwt_in_cookies:
            raise RuntimeWarning(
                "unset_refresh_cookies() called without 'authjwt_token_location' configured to use cookies"
            )

        if response and not isinstance(response, Response):
            raise TypeError("The response must be an object response FastAPI")

        response = response or self._response

        logger.debug("Deleting refresh token cookie")
        response.delete_cookie(
            self._refresh_cookie_key,
            path=self._refresh_cookie_path,
            domain=self._cookie_domain,
            secure=self._cookie_secure,
            httponly=True,
            samesite=self._cookie_samesite,
        )

        if self._cookie_csrf_protect:
            logger.debug("Deleting refresh CSRF token cookie")
            response.delete_cookie(
                self._refresh_csrf_cookie_key,
                path=self._refresh_csrf_cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=True,
                samesite=self._cookie_samesite,
            )

    def _verify_and_get_jwt_optional_in_cookies(
        self,
        request: Union[HTTPConnection, WebSocket],
        csrf_token: Optional[str] = None,
    ) -> "AuthJWT":
        """
        - Optionally check if cookies have a valid access token. If an access token is present in
        cookies, self._token will be set.
        - Raise an exception error when an access token is invalid
        or doesn't match the double submitted CSRF token.

        :param request: for identity get cookies from HTTP or WebSocket
        :param csrf_token: the CSRF double submit token
        """
        logger.debug("Optionally verify and get JWT from cookies")
        logger.debug("request: %s", request)
        logger.debug("csrf_token: %s", csrf_token)

        if not isinstance(request, (HTTPConnection, WebSocket)):
            logger.error(
                "request must be an instance of 'HTTPConnection' or 'WebSocket'"
            )
            raise TypeError(
                "request must be an instance of 'HTTPConnection' or 'WebSocket'"
            )

        cookie_key = self._access_cookie_key
        logger.debug("cookie_key: %s", cookie_key)

        cookie = request.cookies.get(cookie_key)
        logger.debug("cookie: %s", cookie)

        if not isinstance(request, WebSocket):
            csrf_token = request.headers.get(self._access_csrf_header_name)
            logger.debug("csrf_token from headers: %s", csrf_token)

        if cookie and self._cookie_csrf_protect and not csrf_token:
            if (
                isinstance(request, WebSocket)
                or request.scope["method"] in self._csrf_methods
            ):
                logger.error("Missing CSRF Token")
                raise CSRFError(status_code=401, message="Missing CSRF Token")

        # set token from cookie and verify jwt
        self._token = cookie
        logger.debug("self._token set to: %s", self._token)

        self._verify_jwt_optional_in_request(self._token)
        logger.debug("JWT verified")

        decoded_token = self.get_raw_jwt()
        logger.debug("decoded_token: %s", decoded_token)

        if decoded_token and self._cookie_csrf_protect and csrf_token:
            if (
                isinstance(request, WebSocket)
                or request.scope["method"] in self._csrf_methods
            ):
                if "csrf" not in decoded_token:
                    logger.error("Missing claim: csrf")
                    raise JWTDecodeError(status_code=422, message="Missing claim: csrf")
                if not hmac.compare_digest(csrf_token, decoded_token["csrf"]):
                    logger.error("CSRF double submitted tokens do not match")
                    raise CSRFError(
                        status_code=401,
                        message="CSRF double submitted tokens do not match",
                    )

        logger.debug("Finished optionally verifying and getting JWT from cookies")

    def _verify_and_get_jwt_in_cookies(
        self,
        type_token: str,
        request: Union[HTTPConnection, WebSocket],
        csrf_token: Optional[str] = None,
        fresh: Optional[bool] = False,
    ) -> "AuthJWT":
        """
        - Check if cookies have a valid access or refresh token. If there is a token present in
        cookies, self._token will be set.
        - Raise an exception error when an access or refresh token
        is invalid or doesn't match the double submitted CSRF token.

        :param type_token: indicate token is access or refresh token
        :param request: for identity get cookies from HTTP or WebSocket
        :param csrf_token: the CSRF double submit token
        :param fresh: check freshness token if True
        """
        logger.debug("Verify and get JWT from cookies")
        logger.debug("type_token: %s", type_token)
        # Check if request is a valid object with headers
        if hasattr(request, 'headers'):
            request_headers = dict(request.headers)
            logger.debug("Request Headers: %s", request_headers)
        else:
            request_headers = None  # or handle it as needed
            logger.debug("No Request Headers.")
        logger.debug("csrf_token: %s", csrf_token)
        logger.debug("fresh: %s", fresh)

        # Validate input
        if type_token not in ["access", "refresh"]:
            logger.error("type_token must be 'access' or 'refresh'")
            raise ValueError("type_token must be 'access' or 'refresh'")
        if not isinstance(request, (HTTPConnection, WebSocket)):
            logger.error(
                "request must be an instance of 'HTTPConnection' or 'WebSocket'"
            )
            raise TypeError(
                "request must be an instance of 'HTTPConnection' or 'WebSocket'"
            )

        # Initialize cookie_key with a default value
        cookie_key = None

        # Get token type and CSRF token, set cookie_key. If request does NOT come from WebSocket, grab the CSRF value from the header.
        logger.debug(f"Token type is: {type_token}")
        if type_token == "access":
            logger.debug("Setting cookie_key to '_access_cookie_key'")
            cookie_key = self._access_cookie_key
            if not isinstance(request, WebSocket):
                logger.debug(f"Setting csrf_token to {self._access_csrf_header_name}")
                csrf_token = request.headers.get(self._access_csrf_header_name)
        if type_token == "refresh":
            logger.debug(f"Setting cookie_key to {self._refresh_cookie_key}")
            cookie_key = self._refresh_cookie_key
            if not isinstance(request, WebSocket):
                logger.debug(
                    "Setting csrf_token to 'request.headers.get(self._refresh_csrf_header_name)'"
                )
                csrf_token = request.headers.get(self._refresh_csrf_header_name)

        logger.debug(f"cookie_key: {cookie_key}")

        # Set cookie variable, validate it is not None (aka null/empty)
        cookie = request.cookies.get(cookie_key)
        logger.debug(f"Cookie value is: {cookie}")
        if not cookie:
            logger.error("Missing or incorrect cookie. Expected: %s", cookie_key)
            raise MissingTokenError(
                status_code=401,
                message="Missing or incorrect cookie. Expected: {}".format(cookie_key),
            )

        if self._cookie_csrf_protect and not csrf_token:
            if (
                isinstance(request, WebSocket)
                or request.scope["method"] in self._csrf_methods
            ):
                logger.error("Missing CSRF Token")
                raise CSRFError(status_code=401, message="Missing CSRF Token")

        # set token from cookie and verify jwt
        self._token = cookie
        logger.debug("self._token set to: %s", self._token)

        self._verify_jwt_in_request(self._token, type_token, "cookies", fresh)
        logger.debug("JWT verified")

        decoded_token = self.get_raw_jwt()
        logger.debug("decoded_token: %s", decoded_token)

        if self._cookie_csrf_protect and csrf_token:
            if (
                isinstance(request, WebSocket)
                or request.scope["method"] in self._csrf_methods
            ):
                if "csrf" not in decoded_token:
                    logger.error("Missing claim: csrf")
                    raise JWTDecodeError(status_code=422, message="Missing claim: csrf")
                if not hmac.compare_digest(csrf_token, decoded_token["csrf"]):
                    logger.error("CSRF double submitted tokens do not match")
                    raise CSRFError(
                        status_code=401,
                        message="CSRF double submitted tokens do not match",
                    )

        logger.debug("Finished verifying and getting JWT from cookies.")

    def _verify_jwt_optional_in_request(self, token: str) -> None:
        """
        Optionally check if this request has a valid access token

        :param token: The encoded JWT
        """
        logger.debug("Verifying JWT optional in request")
        logger.debug("token: %s", token)

        if token:
            logger.debug("Token is present, verifying token")
            self._verifying_token(token)
            logger.debug("Token verified")

            if self._token_type_claim:
                logger.debug("Token type claim is present")
                raw_jwt = self.get_raw_jwt(token)
                logger.debug("raw_jwt: %s", raw_jwt)

                token_type = raw_jwt[self._token_type_claim_name]
                logger.debug("token_type: %s", token_type)

                if token_type != self._access_token_type:
                    logger.error("Only access tokens are allowed")
                    raise AccessTokenRequired(
                        status_code=422, message="Only access tokens are allowed"
                    )

        logger.debug("Finished verifying JWT optional in request")

    def _verify_jwt_in_request(
        self,
        token: str,
        type_token: str,
        token_from: str,
        fresh: Optional[bool] = False,
    ) -> None:
        """
        Ensure that the requester has a valid token. This also check the freshness of the access token

        :param token: The encoded JWT
        :param type_token: indicate token is an 'access' or 'refresh' token
        :param token_from: indicate token from headers cookies, websocket
        :param fresh: check freshness token if True
        """
        logger.debug("Verifying JWT in request")
        logger.debug(
            "token: %s, type_token: %s, token_from: %s, fresh: %s",
            token,
            type_token,
            token_from,
            fresh,
        )

        if type_token not in ["access", "refresh"]:
            logger.error("Invalid type_token: %s", type_token)
            raise ValueError("type_token must be either: 'access' or 'refresh'")
        if token_from not in ["headers", "cookies", "websocket"]:
            logger.error("Invalid token_from: %s", token_from)
            raise ValueError(
                "token_from must be either: 'headers', 'cookies' or 'websocket'"
            )

        if not token:
            logger.debug("Token is missing")
            if token_from == "headers":
                logger.error("Missing token from headers")
                raise MissingTokenError(
                    status_code=401,
                    message="Missing {} Header".format(self._header_name),
                )
            if token_from == "websocket":
                logger.error("Missing token from websocket")
                raise MissingTokenError(
                    status_code=1008,
                    message="Missing {} token from Query or Path".format(type_token),
                )

        # verify jwt
        issuer = self._decode_issuer if type_token == "access" else None
        logger.debug("Verifying token with issuer: %s", issuer)
        self._verifying_token(token, issuer)
        raw_jwt = self.get_raw_jwt(token)
        logger.debug("raw_jwt: %s", raw_jwt)

        if self._token_type_claim:
            token_types = {
                "access": self._access_token_type,
                "refresh": self._refresh_token_type,
            }
            if raw_jwt[self._token_type_claim_name] != token_types[type_token]:
                msg = "Only {} tokens are allowed".format(token_types[type_token])
                logger.error(msg)
                if type_token == "access":
                    raise AccessTokenRequired(status_code=422, message=msg)
                if type_token == "refresh":
                    raise RefreshTokenRequired(status_code=422, message=msg)

        if fresh and not raw_jwt["fresh"]:
            logger.error("Fresh token required")
            raise FreshTokenRequired(status_code=401, message="Fresh token required")

        logger.debug("Finished verifying JWT in request")

    def _verifying_token(
        self, encoded_token: str, issuer: Optional[str] = None
    ) -> None:
        """
        Verify for a valid token then verify is not revoked.

        :param encoded_token: token hash
        :param issuer: expected issuer in the JWT
        """
        logger.debug("Verifying token")
        logger.debug("encoded_token: %s, issuer: %s", encoded_token, issuer)

        logger.debug("Calling '_verified_token()' to decode the token...")
        raw_token = self._verified_token(encoded_token, issuer)
        logger.debug("raw_token: %s", raw_token)

        if self._token_type_claim:
            logger.debug("Token type claim is present")
            if raw_token[self._token_type_claim_name] in self._denylist_token_checks:
                logger.debug("Token is in denylist, checking if revoked")
                self._check_token_is_revoked(raw_token)

        logger.debug("Verifying claims")
        self._verifying_claims(raw_token)
        logger.debug("Verifying roles")
        self._verifying_roles(raw_token)

        logger.debug("Finished verifying token")

    def _verified_token(
        self, encoded_token: str, issuer: Optional[str] = None
    ) -> Dict[str, Union[str, int, bool]]:
        """
        Verified token and catch all error from jwt package and return decode token

        :param encoded_token: token hash
        :param issuer: expected issuer in the JWT

        :return: raw data from the hash token in the form of a dictionary
        """
        logger.debug("Verified token")
        logger.debug("encoded_token: %s, issuer: %s", encoded_token, issuer)

        algorithms = self._decode_algorithms or [self._algorithm]
        logger.debug("algorithms: %s", algorithms)

        try:
            logger.debug("Calling 'get_unverified_jwt_headers()' to obtain only the headers from the JWT...")
            unverified_headers = self.get_unverified_jwt_headers(encoded_token)
            logger.debug("unverified_headers: %s", unverified_headers)
        except Exception as err:
            logger.error("Invalid header error: %s", err)
            raise InvalidHeaderError(status_code=422, message=str(err))

        try:
            logger.debug("Calling '_get_secret_key()' to decode the JWT...")
            # Validate the algorithm in the header
            if unverified_headers["alg"] not in (self._decode_algorithms or [self._algorithm]):
                logger.error("Invalid algorithm from incoming header: %s", unverified_headers["alg"])
                raise JWTDecodeError(status_code=422, message="Invalid algorithm on header")
            secret_key = self._get_secret_key(unverified_headers["alg"], "decode")
            logger.debug("secret_key: %s", secret_key)
        except KeyError as err:
            logger.error("Missing 'alg' header in JWT: %s", err)
            raise JWTDecodeError(status_code=422, message="Missing 'alg' header")
        except Exception as err:
            logger.error("Error getting secret key: %s", err)
            raise

        try:
            logger.debug("Decoding JWT...")
            decoded_token = jwt.decode(
                encoded_token,
                secret_key,
                issuer=issuer,
                audience=self._decode_audience,
                leeway=self._decode_leeway,
                algorithms=algorithms,
            )
            logger.debug("decoded_token: %s", decoded_token)
            return decoded_token
        except ExpiredSignatureError as err:
            logger.error("Expired signature error: %s", err)
            raise JWTDecodeError(status_code=401, message=str(err))
        except Exception as err:
            logger.error("JWT decode error: %s", err)
            raise JWTDecodeError(status_code=422, message=str(err))
        logger.debug("Finished verified token")

    def _verifying_roles(self, raw_token: dict) -> None:
        # decoded_token = self.get_raw_jwt(encoded_token=token)
        logger.debug("Verifying roles")
        if "roles" in raw_token:
            logger.debug("Roles claim is present")
            token_roles = raw_token["roles"] or []
        else:
            logger.debug("Roles claim is missing")
            token_roles = []

        if len(self._required_roles) > 0:
            if not any(x in self._required_roles for x in token_roles):
                logger.error("Not enough permissions")
                raise NotEnoughPermissions(
                    status_code=403, message="Not enough permissions"
                )

    def _verifying_claims(self, raw_token: dict) -> None:
        logger.debug("Verifying claims")
        if len(self._required_claims) > 0:
            for claim in self._required_claims:
                logger.debug("Checking claim: %s", claim)
                if claim not in raw_token or raw_token[claim] is None:
                    raise ClaimsRequired(status_code=422, message="Missing claim: team")

    def jwt_required(
        self,
        auth_from: str = "request",
        token: Optional[str] = None,
        websocket: Optional[WebSocket] = None,
        csrf_token: Optional[str] = None,
        roles: list = [],
        claims: list = [],
    ) -> None:
        """
        Only access token can access this function

        :param auth_from: for identity get token from HTTP or WebSocket
        :param token: the encoded JWT, it's required if the protected endpoint use WebSocket to authorize and get token from Query Url or Path
        :param websocket: an instance of WebSocket, it's required if protected endpoint use a cookie to authorization
        :param csrf_token: the CSRF double submit token. Since WebSocket cannot add specific additional headers, it must pass csrf_token manually to achieve a Query Url or Path
        """
        logger.debug("Protected as: JWT Required")
        logger.debug(
            "auth_from: %s, token: %s, websocket: %s, csrf_token: %s, roles: %s, claims: %s",
            auth_from,
            token,
            websocket,
            csrf_token,
            roles,
            claims,
        )

        self._required_claims = claims
        self._required_roles = roles
        if auth_from == "websocket":
            if websocket:
                logger.debug("Verifying JWT in cookies for websocket")
                self._verify_and_get_jwt_in_cookies("access", websocket, csrf_token)
            else:
                logger.debug("Verifying JWT in request for websocket")
                self._verify_jwt_in_request(token, "access", "websocket")
        if auth_from == "request":
            if len(self._token_location) == 2:
                logger.debug(f"Token location is: {self._token_location}")
                if self._token and self.jwt_in_headers:
                    logger.debug("Verifying JWT from headers")
                    self._verify_jwt_in_request(self._token, "access", "headers")
                if not self._token and self.jwt_in_cookies:
                    logger.debug("Verifying and getting JWT from cookies")
                    self._verify_and_get_jwt_in_cookies("access", self._request)
            else:
                logger.debug(f"Token location is: {self._token_location}")
                if self.jwt_in_headers:
                    logger.debug("Verifying JWT from headers")
                    self._verify_jwt_in_request(self._token, "access", "headers")
                if self.jwt_in_cookies:
                    logger.debug("Verifying and getting JWT from cookies")
                    self._verify_and_get_jwt_in_cookies("access", self._request)

        logger.debug("Finished eval protection for: JWT Required")

    def jwt_optional(
        self,
        auth_from: str = "request",
        token: Optional[str] = None,
        websocket: Optional[WebSocket] = None,
        csrf_token: Optional[str] = None,
        roles: list = [],
        claims: list = [],
    ) -> None:
        """
        If an access token in present in the request you can get data from get_raw_jwt() or get_jwt_subject(),
        If no access token is present in the request, this endpoint will still be called, but
        get_raw_jwt() or get_jwt_subject() will return None

        :param auth_from: for identity get token from HTTP or WebSocket
        :param token: the encoded JWT, it's required if the protected endpoint use WebSocket to
                    authorization and get token from Query Url or Path
        :param websocket: an instance of WebSocket, it's required if protected endpoint use a cookie to authorization
        :param csrf_token: the CSRF double submit token. since WebSocket cannot add specifying additional headers
                        its must be passing csrf_token manually and can achieve by Query Url or Path
        """
        logger.debug("Protected as: JWT Optional")
        logger.debug(
            "auth_from: %s, token: %s, websocket: %s, csrf_token: %s, roles: %s, claims: %s",
            auth_from,
            token,
            websocket,
            csrf_token,
            roles,
            claims,
        )

        self._required_claims = claims
        self._required_roles = roles
        if auth_from == "websocket":
            if websocket:
                logger.debug(
                    "Verifying and getting optional JWT in cookies for websocket"
                )
                self._verify_and_get_jwt_optional_in_cookies(websocket, csrf_token)
            else:
                logger.debug("Verifying optional JWT in request for websocket")
                self._verify_jwt_optional_in_request(token)
        if auth_from == "request":
            if len(self._token_location) == 2:
                logger.debug(f"Token location is: {self._token_location}")
                if self._token and self.jwt_in_headers:
                    logger.debug("Verifying optional JWT from headers")
                    self._verify_jwt_optional_in_request(self._token)
                if not self._token and self.jwt_in_cookies:
                    logger.debug("Verifying and getting optional JWT from cookies")
                    self._verify_and_get_jwt_optional_in_cookies(self._request)
            else:
                logger.debug(f"Token location is: {self._token_location}")
                if self.jwt_in_headers:
                    logger.debug("Verifying optional JWT from headers")
                    self._verify_jwt_optional_in_request(self._token)
                if self.jwt_in_cookies:
                    logger.debug("Verifying and getting optional JWT from cookies")
                    self._verify_and_get_jwt_optional_in_cookies(self._request)

        logger.debug("Finished eval protection for: JWT Optional")

    def jwt_refresh_token_required(
        self,
        auth_from: str = "request",
        token: Optional[str] = None,
        websocket: Optional[WebSocket] = None,
        csrf_token: Optional[str] = None,
        roles: list = [],
        claims: list = [],
    ) -> None:
        """
        This function will ensure that the requester has a valid refresh token
        :param auth_from: for identity get token from HTTP or WebSocket
        :param token: the encoded JWT, it's required if the protected endpoint use WebSocket to
                    authorization and get token from Query Url or Path
        :param websocket: an instance of WebSocket, it's required if protected endpoint use a cookie to authorization
        :param csrf_token: the CSRF double submit token. since WebSocket cannot add specifying additional headers
                        its must be passing csrf_token manually and can achieve by Query Url or Path
        """
        logger.debug("Protected as: JWT Refresh Token Required")
        logger.debug(
            "auth_from: %s, token: %s, websocket: %s, csrf_token: %s, roles: %s, claims: %s",
            auth_from,
            token,
            websocket,
            csrf_token,
            roles,
            claims,
        )

        self._required_claims = claims
        self._required_roles = roles
        if auth_from == "websocket":
            if websocket:
                logger.debug("Verifying and getting JWT in cookies for websocket")
                self._verify_and_get_jwt_in_cookies("refresh", websocket, csrf_token)
            else:
                logger.debug("Verifying JWT in request for websocket")
                self._verify_jwt_in_request(token, "refresh", "websocket")
        if auth_from == "request":
            if len(self._token_location) == 2:
                logger.debug(f"Token location is: {self._token_location}")
                if self._token and self.jwt_in_headers:
                    logger.debug("Verifying JWT in headers")
                    self._verify_jwt_in_request(self._token, "refresh", "headers")
                if not self._token and self.jwt_in_cookies:
                    logger.debug("Verifying and getting JWT in cookies")
                    self._verify_and_get_jwt_in_cookies("refresh", self._request)
            else:
                logger.debug(f"Token location is: {self._token_location}")
                if self.jwt_in_headers:
                    logger.debug("Verifying JWT in headers")
                    self._verify_jwt_in_request(self._token, "refresh", "headers")
                if self.jwt_in_cookies:
                    logger.debug("Verifying and getting JWT in cookies")
                    self._verify_and_get_jwt_in_cookies("refresh", self._request)

        logger.debug("Finished eval protection for: JWT Refresh Token Required")

    def fresh_jwt_required(
        self,
        auth_from: str = "request",
        token: Optional[str] = None,
        websocket: Optional[WebSocket] = None,
        csrf_token: Optional[str] = None,
        roles: list = [],
        claims: list = [],
    ) -> None:
        """
        This function will ensure that the requester has a valid access token and fresh token
        :param auth_from: for identity get token from HTTP or WebSocket
        :param token: the encoded JWT, it's required if the protected endpoint uses WebSocket to
                    auth and get token from Query Url or Path
        :param websocket: an instance of WebSocket, it's required if protected endpoint use a cookie to authorization
        :param csrf_token: the CSRF double submit token. since WebSocket cannot add specifying additional headers
                        its must be passing csrf_token manually and can achieve by Query Url or Path
        """
        logger.debug("Protected as: Fresh JWT Token Required")
        logger.debug(
            "auth_from: %s, token: %s, websocket: %s, csrf_token: %s, roles: %s, claims: %s",
            auth_from,
            token,
            websocket,
            csrf_token,
            roles,
            claims,
        )

        self._required_claims = claims
        self._required_roles = roles
        if auth_from == "websocket":
            if websocket:
                logger.debug("Verifying and getting JWT in cookies for websocket")
                self._verify_and_get_jwt_in_cookies(
                    "access", websocket, csrf_token, True
                )
            else:
                logger.debug("Verifying JWT in request for websocket")
                self._verify_jwt_in_request(token, "access", "websocket", True)
        if auth_from == "request":
            if len(self._token_location) == 2:
                logger.debug(f"Token location is: {self._token_location}")
                if self._token and self.jwt_in_headers:
                    logger.debug("Verifying JWT in headers")
                    self._verify_jwt_in_request(self._token, "access", "headers", True)
                if not self._token and self.jwt_in_cookies:
                    logger.debug("Verifying and getting JWT in cookies")
                    self._verify_and_get_jwt_in_cookies(
                        "access", self._request, fresh=True
                    )
            else:
                logger.debug(f"Token location is: {self._token_location}")
                if self.jwt_in_headers:
                    logger.debug("Verifying JWT in headers")
                    self._verify_jwt_in_request(self._token, "access", "headers", True)
                if self.jwt_in_cookies:
                    logger.debug("Verifying and getting JWT in cookies")
                    self._verify_and_get_jwt_in_cookies(
                        "access", self._request, fresh=True
                    )

        logger.debug("Finished eval protection for: Fresh JWT Token Required")

    def get_raw_jwt(
        self, encoded_token: Optional[str] = None
    ) -> Optional[Dict[str, Union[str, int, bool]]]:
        """
        this will return the python dictionary which has all of the claims of the JWT that is accessing the endpoint.
        If no JWT is currently present, return None instead

        :param encoded_token: The encoded JWT from parameter
        :return: claims of JWT
        """
        token = encoded_token or self._token

        if token:
            logger.debug(f"Getting raw JWT from token: {token}")
            return self._verified_token(token)
        return None

    def get_jti(self, encoded_token: str) -> str:
        """
        Returns the JTI (unique identifier) of an encoded JWT

        :param encoded_token: The encoded JWT from parameter
        :return: string of JTI
        """
        logger.debug("Getting JTI from token: %s", encoded_token)
        return self._verified_token(encoded_token)["jti"]

    def get_jwt_subject(self) -> Optional[Union[str, int]]:
        """
        this will return the subject of the JWT that is accessing this endpoint.
        If no JWT is present, `None` is returned instead.

        :return: sub of JWT
        """
        if self._token:
            logger.debug("Getting JWT subject")
            return self._verified_token(self._token)["sub"]
        return None

    def get_unverified_jwt_headers(self, encoded_token: Optional[str] = None) -> dict:
        """
        Returns the Headers of an encoded JWT without verifying the actual signature of JWT

        :param encoded_token: The encoded JWT to get the Header from
        :return: JWT header parameters as a dictionary
        """
        encoded_token = encoded_token or self._token
        logger.debug("Getting the headers from the token: %s", encoded_token)

        return jwt.get_unverified_header(encoded_token)


class AuthJWTBearer(HTTPBase):
    def __init__(
        self,
        *,
        bearerFormat: Optional[str] = None,
        scheme_name: Optional[str] = None,
        description: Optional[str] = None,
        auto_error: bool = True,
    ):
        self.model = HTTPBearerModel(bearerFormat=bearerFormat, description=description)
        self.scheme_name = scheme_name or self.__class__.__name__
        self.auto_error = auto_error

    def __call__(self, req: HTTPConnection = None, res: Response = None) -> AuthJWT:
        return AuthJWT(req=req, res=res)
