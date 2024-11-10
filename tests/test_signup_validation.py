from unittest.mock import patch

from flask_wtf.csrf import CSRFProtect

# fmt: off
from tests.fixtures.custom_fixture import client  # noqa: F401
from tests.fixtures.custom_fixture import mock_dev_env_vars  # noqa: F401

# fmt: on


def test_signup_successful_validation(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "sign_up",
        return_value={
            "UserConfirmed": False,
            "UserSub": "fake-user-sub-id",
        },
    ):

        # Act: Call the actual logic that calls `sign_up`
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
            "/v1/auth/signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "message" in json_data
        assert (
            json_data["message"]
            == "User registered successfully. Check your email to confirm the account."
        )
        assert "user_sub" in json_data
        assert json_data["user_sub"] == "fake-user-sub-id"


def test_signup_username_exists_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "sign_up",
        side_effect=app.cognito_client.exceptions.UsernameExistsException(
            "User already exists."
        ),
    ):

        # Act: Call the actual logic that calls `sign_up`
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
            "/v1/auth/signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 409


def test_signup_invalid_passowrd_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "sign_up",
        side_effect=app.cognito_client.exceptions.InvalidPasswordException(
            "Invalid Password."
        ),
    ):

        # Act: Call the actual logic that calls `sign_up`
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
            "/v1/auth/signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 400


def test_signup_unknown_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "sign_up",
        side_effect=Exception("A generic error occurred."),
    ):

        # Act: Call the actual logic that calls `sign_up`
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
            "/v1/auth/signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 500


def test_signup_confirmation_success(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_sign_up",
        return_value={
            "UserConfirmed": True,
            "UserSub": "fake-user-sub-id",
        },
    ):

        # Act: Call the actual logic that calls `sign_up confirmation`
        email = "test@example.com"
        confirmation_code = "DummyCode"

        data = {
            "email": email,
            "confirmation_code": confirmation_code,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "message" in json_data
        assert json_data["message"] == "User confirmed successfully."


def test_signup_confirmation_expired_code_exception(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_sign_up",
        side_effect=app.cognito_client.exceptions.ExpiredCodeException(
            "Code Expired"
        ),
    ):

        # Act: Call the actual logic that calls `sign_up confirmation`
        email = "test@example.com"
        confirmation_code = "DummyCode"

        data = {
            "email": email,
            "confirmation_code": confirmation_code,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 400
        assert (
            response.get_json()["error"]
            == "Confirmation code has expired."
        )


def test_signup_confirmation_code_mismatch_exception(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_sign_up",
        side_effect=app.cognito_client.exceptions.CodeMismatchException(
            "Code Expired"
        ),
    ):

        # Act: Call the actual logic that calls `sign_up confirmation`
        email = "test@example.com"
        confirmation_code = "DummyCode"

        data = {
            "email": email,
            "confirmation_code": confirmation_code,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 400
        assert (
            response.get_json()["error"]
            == "Invalid confirmation code."
        )


def test_signup_confirmation_unknown_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_sign_up",
        side_effect=Exception("A generic error occurred."),
    ):

        # Act: Call the actual logic that calls `sign_up confirmation`
        email = "test@example.com"
        confirmation_code = "DummyCode"

        data = {
            "email": email,
            "confirmation_code": confirmation_code,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-signup",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 500
        assert (
            response.get_json()["error"]
            == "A generic error occurred."
        )
