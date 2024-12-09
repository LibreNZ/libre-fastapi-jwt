from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from libre_fastapi_jwt import AuthJWT, AuthJWTBearer
from libre_fastapi_jwt.exceptions import AuthJWTException
from pydantic import BaseModel

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


class Settings(BaseModel):
    authjwt_secret_key: str = "secret"


@AuthJWT.load_config
def get_config():
    return Settings()

auth_dep = AuthJWTBearer()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


# Standard login endpoint. Will return a fresh access token and a refresh token
@app.post("/login")
def login(user: User, Authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    """
    create_access_token supports an optional 'fresh' argument,
    which marks the token as fresh or non-fresh accordingly.
    As we just verified their username and password, we are
    going to mark the token as fresh here.
    """
    access_token = Authorize.create_access_token(subject=user.username, fresh=True)
    refresh_token = Authorize.create_refresh_token(subject=user.username)
    return {"access_token": access_token, "refresh_token": refresh_token}


@app.post("/refresh")
def refresh(Authorize: AuthJWT = Depends(auth_dep)):
    """
    Refresh token endpoint. This will generate a new access token from
    the refresh token, but will mark that access token as non-fresh,
    as we do not actually verify a password in this endpoint.
    """
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user, fresh=False)
    return {"access_token": new_access_token}


@app.post("/fresh-login")
def fresh_login(user: User, Authorize: AuthJWT = Depends(auth_dep)):
    """
    Fresh login endpoint. This is designed to be used if we need to
    make a fresh token for a user (by verifying they have the
    correct username and password). Unlike the standard login endpoint,
    this will only return a new access token, so that we don't keep
    generating new refresh tokens, which entirely defeats the point.
    """
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    new_access_token = Authorize.create_access_token(subject=user.username, fresh=True)
    return {"access_token": new_access_token}


# Any valid JWT access token can access this endpoint
@app.get("/protected")
def protected(Authorize: AuthJWT = Depends(auth_dep)):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}


# Only fresh JWT access token can access this endpoint
@app.get("/protected-fresh")
def protected_fresh(Authorize: AuthJWT = Depends(auth_dep)):
    Authorize.fresh_jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}