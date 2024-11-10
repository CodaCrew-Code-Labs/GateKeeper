from unittest.mock import patch

from flask_wtf.csrf import CSRFProtect

# fmt: off
from tests.fixtures.custom_fixture import client  # noqa: F401
from tests.fixtures.custom_fixture import mock_dev_env_vars  # noqa: F401

# fmt: on


def test_signin_successful_validation(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "initiate_auth",
        return_value={
            "AuthenticationResult": {
                "AccessToken": "DumyyAccessToken",
                "IdToken": "DummyIdToken",
                "RefreshToken": "DummyRefreshToken",
            }
        },
    ), patch.object(
        app.cognito_client,
        "get_user",
        return_value={
            "UserAttributes": [
                {"Name": "custom:app_tag", "Value": "DummyAppTag"}
            ]
        },
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"
        password = "Password123!"
        app_tag = "DummyAppTag"

        data = {
            "email": email,
            "password": password,
            "app_tag": app_tag,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/signin",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "access_token" in json_data
        assert "id_token" in json_data
        assert "refresh_token" in json_data


def test_signin_app_not_authorized(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "initiate_auth",
        return_value={
            "AuthenticationResult": {
                "AccessToken": "DumyyAccessToken",
                "IdToken": "DummyIdToken",
                "RefreshToken": "DummyRefreshToken",
            }
        },
    ), patch.object(
        app.cognito_client,
        "get_user",
        return_value={
            "UserAttributes": [
                {"Name": "custom:app_tag", "Value": "DummyAppTag"}
            ]
        },
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"
        password = "Password123!"
        app_tag = "my-app-tag"

        data = {
            "email": email,
            "password": password,
            "app_tag": app_tag,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/signin",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 403
        assert (
            response.get_json()["error"]
            == "User not authorized to use this App"
        )


def test_signin_not_authorized_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "initiate_auth",
        side_effect=app.cognito_client.exceptions.NotAuthorizedException(
            "Invalid Credentials."
        ),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"
        password = "Password123!"
        app_tag = "my-app-tag"

        data = {
            "email": email,
            "password": password,
            "app_tag": app_tag,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/signin",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # # Assert the response
        assert response.status_code == 401
        assert response.get_json()["error"] == "Invalid credentials."


def test_signin_unknown_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "initiate_auth",
        side_effect=Exception("A generic error occurred."),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"
        password = "Password123!"
        app_tag = "my-app-tag"

        data = {
            "email": email,
            "password": password,
            "app_tag": app_tag,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/signin",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # # Assert the response
        assert response.status_code == 500
        assert (
            response.get_json()["error"]
            == "A generic error occurred."
        )
