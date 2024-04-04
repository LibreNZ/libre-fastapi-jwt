from fastapi import FastAPI, WebSocket, Depends, Query
from fastapi.responses import HTMLResponse
from libre_fastapi_jwt import AuthJWT, AuthJWTBearer
from libre_fastapi_jwt.exceptions import AuthJWTException
from pydantic import BaseModel

app = FastAPI()

class User(BaseModel):
    username: str
    password: str

class Settings(BaseModel):
    authjwt_secret_key: str = "secret"
    authjwt_token_location: set = {"cookies"}


@AuthJWT.load_config
def get_config():
    return Settings()

auth_dep = AuthJWTBearer()

html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Authorize</title>
    </head>
    <body>
        <h1>WebSocket Authorize</h1>
        <button onclick="websocketfun()">Send</button>
        <ul id='messages'>
        </ul>
        <script>
            const getCookie = (name) => {
                const value = `; ${document.cookie}`;
                const parts = value.split(`; ${name}=`);
                if (parts.length === 2) return parts.pop().split(';').shift();
            }

            const websocketfun = () => {
                let csrf_token = getCookie("csrf_access")

                let ws = new WebSocket(`ws://localhost:8000/ws?csrf_token=${csrf_token}`)
                ws.onmessage = (event) => {
                    let messages = document.getElementById('messages')
                    let message = document.createElement('li')
                    let content = document.createTextNode(event.data)
                    message.appendChild(content)
                    messages.appendChild(message)
                }
            }
        </script>
    </body>
</html>
"""


@app.get("/")
async def get():
    return HTMLResponse(html)


@app.websocket("/ws")
async def websocket(
    websocket: WebSocket, csrf_token: str = Query(...), Authorize: AuthJWT = Depends(auth_dep)
):
    await websocket.accept()
    try:
        Authorize.jwt_required("websocket", websocket=websocket, csrf_token=csrf_token)
        # Authorize.jwt_optional("websocket",websocket=websocket,csrf_token=csrf_token)
        # Authorize.jwt_refresh_token_required("websocket",websocket=websocket,csrf_token=csrf_token)
        # Authorize.fresh_jwt_required("websocket",websocket=websocket,csrf_token=csrf_token)
        await websocket.send_text("Successful Login!")
        decoded_token = Authorize.get_raw_jwt()
        await websocket.send_text(f"Here's your decoded token: {decoded_token}")
    except AuthJWTException as err:
        await websocket.send_text(err.message)
        await websocket.close()


# provide a method to create access tokens. The create_<type>_token()
# function is used to actually generate the token to use authorization
# later in endpoint protected
@app.post("/login")
def login(user: User, Authorize: AuthJWT = Depends(auth_dep)):
    if user.username != "test" or user.password != "test":
        raise HTTPException(status_code=401, detail="Bad username or password")

    # subject identifier for who this token is for example id or username from database
    #access_token = Authorize.create_access_token(subject=user.username)
    #refresh_token = Authorize.create_refresh_token(subject=user.username)
    # Call pair creation
    pair_token = Authorize.create_pair_token(subject=user.username, fresh=True)

    # Set the JWT cookies in the response
    #Authorize.set_access_cookies(access_token)
    #Authorize.set_refresh_cookies(refresh_token)
    Authorize.set_pair_cookies(pair_token)
    
    #return {"tokens": access_token, "msg": "Successful login. Refresh token set as cookie. :)"}
    return {"tokens": pair_token, "msg": "Successful login. Access and Refresh token set as cookies. :)"}

