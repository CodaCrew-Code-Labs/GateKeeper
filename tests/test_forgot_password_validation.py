from unittest.mock import patch

from flask_wtf.csrf import CSRFProtect

# fmt: off
from tests.fixtures.custom_fixture import client  # noqa: F401
from tests.fixtures.custom_fixture import mock_dev_env_vars  # noqa: F401

# fmt: on


def test_forgot_password_successful_validation(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(app.cognito_client, "forgot_password"):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"

        data = {"email": email}

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "message" in json_data
        assert (
            json_data["message"]
            == "Password reset code sent to email."
        )


def test_forgot_password_user_notfound_exception(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "forgot_password",
        side_effect=app.cognito_client.exceptions.UserNotFoundException(
            "User Not Found."
        ),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"

        data = {"email": email}

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 404
        json_data = response.get_json()
        assert "error" in json_data
        assert json_data["error"] == "User does not exist."


def test_forgot_password_unknown_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "forgot_password",
        side_effect=Exception("A generic error occurred."),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"

        data = {"email": email}

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 500
        json_data = response.get_json()
        assert "error" in json_data
        assert json_data["error"] == "A generic error occurred."


def test_confirm_forgot_password_successful_validation(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(app.cognito_client, "confirm_forgot_password"):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"
        confirmation_code = "dummycode"
        new_password = "dummypassword"

        data = {
            "email": email,
            "confirmation_code": confirmation_code,
            "new_password": new_password,
        }

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 200
        json_data = response.get_json()
        assert "message" in json_data
        assert (
            json_data["message"]
            == "Password has been reset successfully."
        )


def test_confirm_forgot_password_code_mismatch_exception(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_forgot_password",
        side_effect=app.cognito_client.exceptions.CodeMismatchException(
            "Code Mismatch."
        ),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"

        data = {"email": email}

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 400
        json_data = response.get_json()
        assert "error" in json_data
        assert json_data["error"] == "Invalid confirmation code."


def test_confirm_forgot_password_expired_code_exception(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_forgot_password",
        side_effect=app.cognito_client.exceptions.ExpiredCodeException(
            "Code Expired."
        ),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"

        data = {"email": email}

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 400
        json_data = response.get_json()
        assert "error" in json_data
        assert json_data["error"] == "Confirmation code has expired."


def test_confirm_forgot_password_unknown_exception(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application
    with patch.object(
        CSRFProtect, "protect", lambda x: None
    ), patch.object(
        app.cognito_client,
        "confirm_forgot_password",
        side_effect=Exception("A generic error occurred."),
    ):

        # Act: Call the actual logic that calls `signin`
        email = "test@example.com"

        data = {"email": email}

        # Now, make the POST request using the test client
        response = client.post(
            "/v1/auth/confirm-forgot-password",
            json=data,
            headers={"X-CSRF-Token": "dummy_csrf_token"},
        )

        # Assert the response
        assert response.status_code == 500
        json_data = response.get_json()
        assert "error" in json_data
        assert json_data["error"] == "A generic error occurred."
