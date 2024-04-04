from fastapi import APIRouter, Depends, HTTPException
from libre_fastapi_jwt import AuthJWT, AuthJWTBearer
from pydantic import BaseModel


class User(BaseModel):
    username: str
    password: str


router = APIRouter()

auth_dep = AuthJWTBearer()

@router.post("/login")
def login(user: User, Authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    access_token = Authorize.create_access_token(subject=user.username)
    return {"access_token": access_token}
