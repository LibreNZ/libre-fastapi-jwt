import pytest, jwt
from fastapi_jwt2 import AuthJWT
from datetime import timedelta, datetime, timezone
from pydantic_settings import BaseSettings


@pytest.fixture()
def test_settings() -> None:
    class Settings(BaseSettings):
        AUTHJWT_SECRET_KEY: str = "testing"
        AUTHJWT_ACCESS_TOKEN_EXPIRES: int = 2
        AUTHJWT_REFRESH_TOKEN_EXPIRES: int = 4

    @AuthJWT.load_config
    def get_settings():
        return Settings()


def test_create_access_token(Authorize, test_settings):

    with pytest.raises(TypeError, match=r"missing 1 required positional argument"):
        Authorize.create_access_token()

    with pytest.raises(TypeError, match=r"subject"):
        Authorize.create_access_token(subject=0.123)

    with pytest.raises(TypeError, match=r"fresh"):
        Authorize.create_access_token(subject="test", fresh="lol")

    with pytest.raises(TypeError, match=r"headers must be a dict"):
        Authorize.create_access_token(subject=1, headers="test")


def test_create_refresh_token(Authorize, test_settings):
    with pytest.raises(TypeError, match=r"missing 1 required positional argument"):
        Authorize.create_refresh_token()

    with pytest.raises(TypeError, match=r"subject"):
        Authorize.create_refresh_token(subject=0.123)

    with pytest.raises(TypeError, match=r"headers must be a dict"):
        Authorize.create_refresh_token(subject=1, headers="test")


def test_create_pair_token(Authorize, test_settings):
    with pytest.raises(TypeError, match=r"missing 1 required positional argument"):
        Authorize.create_pair_token()

    with pytest.raises(TypeError, match=r"subject"):
        Authorize.create_pair_token(subject=0.123)

    with pytest.raises(TypeError, match=r"fresh"):
        Authorize.create_pair_token(subject="test", fresh="lol")

    with pytest.raises(TypeError, match=r"headers must be a dict"):
        Authorize.create_pair_token(subject=1, headers="test")


def test_create_dynamic_access_token_expires(Authorize, test_settings):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_access_token(subject=1, expires_time=90)
    assert jwt.decode(token, "testing", algorithms="HS256")["exp"] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_access_token(subject=1, expires_time=timedelta(days=1))
    assert jwt.decode(token, "testing", algorithms="HS256")["exp"] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 2
    token = Authorize.create_access_token(subject=1, expires_time=True)
    assert jwt.decode(token, "testing", algorithms="HS256")["exp"] == expires_time

    token = Authorize.create_access_token(subject=1, expires_time=False)
    assert "exp" not in jwt.decode(token, "testing", algorithms="HS256")

    with pytest.raises(TypeError, match=r"expires_time"):
        Authorize.create_access_token(subject=1, expires_time="test")


def test_create_dynamic_refresh_token_expires(Authorize, test_settings):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_refresh_token(subject=1, expires_time=90)
    assert jwt.decode(token, "testing", algorithms="HS256")["exp"] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_refresh_token(subject=1, expires_time=timedelta(days=1))
    assert jwt.decode(token, "testing", algorithms="HS256")["exp"] == expires_time

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 4
    token = Authorize.create_refresh_token(subject=1, expires_time=True)
    assert jwt.decode(token, "testing", algorithms="HS256")["exp"] == expires_time

    token = Authorize.create_refresh_token(subject=1, expires_time=False)
    assert "exp" not in jwt.decode(token, "testing", algorithms="HS256")

    with pytest.raises(TypeError, match=r"expires_time"):
        Authorize.create_refresh_token(subject=1, expires_time="test")


def test_create_dynamic_pair_token_expires(Authorize, test_settings):
    expires_time = int(datetime.now(timezone.utc).timestamp()) + 90
    token = Authorize.create_pair_token(subject=1, expires_time=90)
    assert_access_token = jwt.decode(token["access_token"], "testing", algorithms="HS256")["exp"] == expires_time
    assert_refresh_token = jwt.decode(token["refresh_token"], "testing", algorithms="HS256")["exp"] == expires_time
    assert assert_access_token and assert_refresh_token

    expires_time = int(datetime.now(timezone.utc).timestamp()) + 86400
    token = Authorize.create_pair_token(subject=1, expires_time=timedelta(days=1))
    assert_access_token = jwt.decode(token["access_token"], "testing", algorithms="HS256")["exp"] == expires_time
    assert_refresh_token = jwt.decode(token["refresh_token"], "testing", algorithms="HS256")["exp"] == expires_time
    assert assert_access_token and assert_refresh_token

    # Set different timestamps to test both token types
    expires_time_access = int(datetime.now(timezone.utc).timestamp()) + 2
    expires_time_refresh = int(datetime.now(timezone.utc).timestamp()) + 4
    token = Authorize.create_pair_token(subject=1, expires_time=True)
    assert_access_token = jwt.decode(token["access_token"], "testing", algorithms="HS256")["exp"] == expires_time_access
    assert_refresh_token = (
        jwt.decode(token["refresh_token"], "testing", algorithms="HS256")["exp"] == expires_time_refresh
    )
    assert assert_access_token and assert_refresh_token

    token = Authorize.create_pair_token(subject=1, expires_time=False)
    assert "exp" not in jwt.decode(token["access_token"], "testing", algorithms="HS256")
    assert "exp" not in jwt.decode(token["refresh_token"], "testing", algorithms="HS256")

    with pytest.raises(TypeError, match=r"expires_time"):
        Authorize.create_pair_token(subject=1, expires_time="test")


def test_create_token_invalid_type_data_audience(Authorize, test_settings):
    with pytest.raises(TypeError, match=r"audience"):
        Authorize.create_access_token(subject=1, audience=1)

    with pytest.raises(TypeError, match=r"audience"):
        Authorize.create_refresh_token(subject=1, audience=1)


def test_create_token_invalid_algorithm(Authorize, test_settings):
    with pytest.raises(ValueError, match=r"Algorithm"):
        Authorize.create_access_token(subject=1, algorithm="test")

    with pytest.raises(ValueError, match=r"Algorithm"):
        Authorize.create_refresh_token(subject=1, algorithm="test")


def test_create_token_invalid_type_data_algorithm(Authorize, test_settings):
    with pytest.raises(TypeError, match=r"algorithm"):
        Authorize.create_access_token(subject=1, algorithm=1)

    with pytest.raises(TypeError, match=r"algorithm"):
        Authorize.create_refresh_token(subject=1, algorithm=1)


def test_create_token_invalid_user_claims(Authorize, test_settings):
    with pytest.raises(TypeError, match=r"user_claims"):
        Authorize.create_access_token(subject=1, user_claims="asd")
    with pytest.raises(TypeError, match=r"user_claims"):
        Authorize.create_refresh_token(subject=1, user_claims="asd")


def test_create_valid_user_claims(Authorize, test_settings):
    access_token = Authorize.create_access_token(subject=1, user_claims={"my_access": "yeah"})
    refresh_token = Authorize.create_refresh_token(subject=1, user_claims={"my_refresh": "hello"})
    pair_token = Authorize.create_pair_token(subject=1, user_claims={"my_access": "yeah", "my_refresh": "hello"})

    assert jwt.decode(access_token, "testing", algorithms="HS256")["my_access"] == "yeah"
    assert jwt.decode(refresh_token, "testing", algorithms="HS256")["my_refresh"] == "hello"
    assert jwt.decode(pair_token["access_token"], "testing", algorithms="HS256")["my_access"] == "yeah"
    assert jwt.decode(pair_token["refresh_token"], "testing", algorithms="HS256")["my_refresh"] == "hello"
