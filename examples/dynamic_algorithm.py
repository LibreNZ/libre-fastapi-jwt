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
    # Configure algorithms which is permit
    authjwt_decode_algorithms: set = {"HS384", "HS512"}


@AuthJWT.load_config
def get_config():
    return Settings()

auth_dep = AuthJWTBearer()

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.post("/login")
def login(user: User, Authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # You can define different algorithm when create a token
    access_token = Authorize.create_access_token(
        subject=user.username, algorithm="HS384"
    )
    refresh_token = Authorize.create_refresh_token(
        subject=user.username, algorithm="HS512"
    )
    return {"access_token": access_token, "refresh_token": refresh_token}


# In protected route, automatically check incoming JWT
# have algorithm in your `authjwt_decode_algorithms` or not
@app.post("/refresh")
def refresh(Authorize: AuthJWT = Depends(auth_dep)):
    Authorize.jwt_refresh_token_required()

    current_user = Authorize.get_jwt_subject()
    new_access_token = Authorize.create_access_token(subject=current_user)
    return {"access_token": new_access_token}


# In protected route, automatically check incoming JWT
# have algorithm in your `authjwt_decode_algorithms` or not
@app.get("/protected")
def protected(Authorize: AuthJWT = Depends(auth_dep)):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}