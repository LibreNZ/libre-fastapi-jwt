import pytest
import logging
from libre_fastapi_jwt import AuthJWT
from fastapi import FastAPI, Depends, Request # type: ignore
from fastapi.testclient import TestClient # type: ignore

logging.basicConfig(level=logging.DEBUG)

@pytest.fixture(scope="function")
def client():
    app = FastAPI()

    @app.get("/get-token")
    def get_token(Authorize: AuthJWT = Depends()):
        access_token = Authorize.create_access_token(subject=1, fresh=True)
        refresh_token = Authorize.create_refresh_token(subject=1)

        Authorize.set_access_cookies(access_token)
        Authorize.set_refresh_cookies(refresh_token)
        logging.debug(f"access_token: {access_token}, refresh_token: {refresh_token}")
        return {"access": access_token, "refresh": refresh_token}

    @app.post("/jwt-optional")
    def jwt_optional(Authorize: AuthJWT = Depends()):
        Authorize.jwt_optional()
        return {"hello": Authorize.get_jwt_subject()}

    @app.post("/jwt-required")
    def jwt_required(Authorize: AuthJWT = Depends()):
        Authorize.jwt_required()
        return {"hello": Authorize.get_jwt_subject()}

    @app.post("/jwt-refresh")
    async def jwt_refresh(request: Request, Authorize: AuthJWT = Depends()):
        # Extract request headers and body
        request_headers = dict(request.headers)
        request_body = await request.body()

        # Log the request details
        logging.debug(f"Request Headers: {request_headers}")

        # Perform the JWT refresh token check
        Authorize.jwt_refresh_token_required()
        response_body = {"hello": Authorize.get_jwt_subject()}

        # Return all the information
        return response_body

    @app.post("/jwt-fresh")
    def jwt_fresh(Authorize: AuthJWT = Depends()):
        Authorize.fresh_jwt_required()
        return {"hello": Authorize.get_jwt_subject()}
    
    @app.get("/get-accesstoken-and-refreshcookie")
    def get_token(Authorize: AuthJWT = Depends()):
        pair_token = Authorize.create_pair_token(subject=1)
        access_token = pair_token["access_token"]
        refresh_token = pair_token["refresh_token"]

        Authorize.set_refresh_cookies(refresh_token)
        logging.debug(f"access_token: {access_token}, refresh_token: {refresh_token}")
        return {"access": access_token, "refresh": refresh_token}

    client = TestClient(app)
    return client


@pytest.mark.parametrize(
    "url", ["/jwt-optional", "/jwt-required", "/jwt-refresh", "/jwt-fresh"]
)
def test_get_subject_through_cookie_or_headers(url, client):
    @AuthJWT.load_config
    def get_secret_key():
        return [
            ("authjwt_secret_key", "secret"),
            ("authjwt_token_location", ["headers", "cookies"]),
            ("authjwt_cookie_secure", False),
        ]

    res = client.get("/get-token")
    access_token = res.json()["access"]
    refresh_token = res.json()["refresh"]

    access_csrf = res.cookies.get("csrf_access")
    refresh_csrf = res.cookies.get("csrf_refresh")

    # access through headers
    if url != "/jwt-refresh":
        response = client.post(url, headers={"Authorization": f"Bearer {access_token}"})
    else:
        response = client.post(
            url, headers={"Authorization": f"Bearer {refresh_token}"}
        )

    assert response.status_code == 200
    assert response.json() == {"hello": 1}

    # access through cookies
    if url != "/jwt-refresh":
        response = client.post(url, headers={"X-CSRF-Token": access_csrf})
    else:
        response = client.post(url, headers={"X-CSRF-Token": refresh_csrf})

    assert response.status_code == 200
    assert response.json() == {"hello": 1}


@pytest.mark.parametrize(
    "url", ["/jwt-refresh"]
)
def test_refresh_access_token_refresh_cookie(url, client):
    @AuthJWT.load_config
    def get_secret_key():
        return [
            ("authjwt_secret_key", "secret"),
            ("authjwt_token_location", ["headers", "cookies"]),
            ("authjwt_cookie_secure", False),
        ]

    res = client.get("/get-accesstoken-and-refreshcookie")
    # Grab tokens from response
    #access_token = res.json()["access"]
    #refresh_token = res.json()["refresh"]
    # Grab CSRF refresh token from cookie
    refresh_csrf = res.cookies.get("csrf_refresh")

    # Try access through cookies
    response = client.post(url, headers={"X-CSRF-Token": refresh_csrf})

    assert response.status_code == 200
    assert response.json() == {"hello": 1}
