import pytest, jwt, os
from libre_fastapi_jwt import AuthJWT
from libre_fastapi_jwt.exceptions import AuthJWTException
from fastapi import FastAPI, Depends, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from pydantic_settings import BaseSettings


@pytest.fixture(scope="function")
def client():
    app = FastAPI()

    @app.exception_handler(AuthJWTException)
    def authjwt_exception_handler(request: Request, exc: AuthJWTException):
        return JSONResponse(
            status_code=exc.status_code, content={"detail": exc.message}
        )

    @app.get("/protected")
    def protected(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {"hello": "world"}

    return TestClient(app)


def test_kid_in_header_not_body_symmetric(Authorize):
    """kid must appear in the JOSE header, not the JWT payload (RFC 7515 §4.1)."""
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "test-secret"

    @AuthJWT.load_config
    def load():
        return Settings()

    token = Authorize.create_access_token(subject="test")

    # kid should be in the JOSE header
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    assert header["kid"] == "whoamikidding"  # fallback for symmetric keys

    # kid should NOT be in the payload body
    decoded = jwt.decode(token, "test-secret", algorithms=["HS256"])
    assert "kid" not in decoded


def test_kid_in_header_asymmetric(Authorize):
    """With asymmetric keys, kid should be the public key thumbprint in the JOSE header."""
    DIR = os.path.abspath(os.path.dirname(__file__))
    with open(os.path.join(DIR, "private_key.txt")) as f:
        PRIVATE_KEY = f.read().strip()
    with open(os.path.join(DIR, "public_key.txt")) as f:
        PUBLIC_KEY = f.read().strip()

    class Settings(BaseSettings):
        authjwt_algorithm: str = "RS256"
        authjwt_private_key: str = PRIVATE_KEY
        authjwt_public_key: str = PUBLIC_KEY

    @AuthJWT.load_config
    def load():
        return Settings()

    token = Authorize.create_access_token(subject="test")

    # kid should be in the JOSE header with a real thumbprint
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    assert header["kid"] != "whoamikidding"
    assert len(header["kid"]) > 10  # SHA-256 thumbprint is 43 chars base64url

    # kid should NOT be in the payload body
    decoded = jwt.decode(token, PUBLIC_KEY, algorithms=["RS256"])
    assert "kid" not in decoded


def test_kid_validation_rejects_wrong_kid(client, Authorize):
    """When authjwt_decode_kid is set, tokens with wrong kid are rejected."""
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "test-secret"
        AUTHJWT_DECODE_KID: str = "expected-kid"

    @AuthJWT.load_config
    def load():
        return Settings()

    # Create a token (will have kid "whoamikidding" since symmetric)
    token = Authorize.create_access_token(subject="test")

    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid kid on header"}


def test_kid_validation_accepts_matching_kid(client, Authorize):
    """When authjwt_decode_kid matches the token's kid, verification succeeds."""
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "test-secret"
        AUTHJWT_DECODE_KID: str = "whoamikidding"

    @AuthJWT.load_config
    def load():
        return Settings()

    token = Authorize.create_access_token(subject="test")

    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}


def test_kid_validation_disabled_by_default(client, Authorize):
    """Without authjwt_decode_kid set, any kid is accepted."""
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "test-secret"

    @AuthJWT.load_config
    def load():
        return Settings()

    token = Authorize.create_access_token(subject="test")

    response = client.get(
        "/protected", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json() == {"hello": "world"}
