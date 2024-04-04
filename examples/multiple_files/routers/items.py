from fastapi import APIRouter, Depends
from libre_fastapi_jwt import AuthJWT, AuthJWTBearer

router = APIRouter()
auth_dep = AuthJWTBearer()

@router.get("/items")
def items(Authorize: AuthJWT = Depends(auth_dep)):
    Authorize.jwt_required()

    items = ["item1", "item2", "item3"]

    return {"items": items}
