from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import JSONResponse
from fastapi_jwt2 import AuthJWT
from fastapi_jwt2.exceptions import AuthJWTException
from pydantic import BaseModel
from datetime import timedelta

app = FastAPI()


class User(BaseModel):
    username: str
    password: str


# in production you can use Settings management
# from pydantic to get secret key from .env
class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_token_location: set = {"cookies", "headers"}
    authjwt_cookie_secure: bool = True
    authjwt_cookie_csrf_protect: bool = False
    authjwt_cookie_samesite: str = "strict"
    authjwt_cookie_max_age: int = 604800  # 7 days = 604800 seconds
    authjwt_refresh_token_expires: timedelta = timedelta(days=14)
    authjwt_access_csrf_cookie_key: str = "csrf_access"
    authjwt_refresh_csrf_cookie_key: str = "csrf_refresh"
    authjwt_access_csrf_header_name: str = "X-Libre-AccessToken"
    authjwt_refresh_csrf_header_name: str = "X-Libre-RefreshToken"


# callback to get your configuration
@AuthJWT.load_config
def get_config():
    return Settings()


# exception handler for authjwt
# in production, you can tweak performance using orjson response
@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


# provide a method to create access tokens. The create_<type>_token()
# function is used to actually generate the token to use authorization
# later in endpoint protected
@app.post("/login")
def login(user: User, Authorize: AuthJWT = Depends()):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # subject identifier for who this token is for example id or username from database
    # access_token = Authorize.create_access_token(subject=user.username)
    # refresh_token = Authorize.create_refresh_token(subject=user.username)
    # Call pair creation
    pair_token = Authorize.create_pair_token(subject=user.username)

    # Set the JWT cookies in the response
    # Authorize.set_access_cookies(access_token)
    # Authorize.set_refresh_cookies(refresh_token)
    Authorize.set_pair_cookies(pair_token)

    # return {"tokens": access_token, "msg": "Successful login. Refresh token set as cookie. :)"}
    return {"tokens": pair_token, "msg": "Successful login. Access and Refresh token set as cookies. :)"}


# protect endpoint with function jwt_required(), which requires
# a valid access token in the request headers to access.
@app.get("/user")
def user(Authorize: AuthJWT = Depends()):
    Authorize.jwt_required()

    current_user = Authorize.get_jwt_subject()
    return {"user": current_user}


# If CSRF protection is True, this won't work unless the DELETE request comes with a header that includes the csrf token in the cookies.
# Something along the lines of `https://localhost:8000/logout?X-CSRF-Token=${csrf_token}`
@app.delete("/logout")
def logout(Authorize: AuthJWT = Depends()):
    """
    Because the JWT are stored in an httponly cookie now, we cannot
    log the user out by simply deleting the cookies in the frontend.
    We need the backend to send us a response to delete the cookies.
    """
    Authorize.jwt_required()

    Authorize.unset_jwt_cookies()
    return {"msg": "Successful logout. All cookies have been deleted."}
