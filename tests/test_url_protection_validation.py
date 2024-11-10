from unittest.mock import patch

from flask_wtf.csrf import CSRFProtect

# fmt: off
from tests.fixtures.custom_fixture import client  # noqa: F401
from tests.fixtures.custom_fixture import mock_dev_env_vars  # noqa: F401

# fmt: on


def test_verify_user_token_successful_validation(
    client,  # noqa: F811
):
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch(
            "app.v1.routes.verify_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = [
                "dummy_user",
                "dummy_value",
            ]

            # Now, make the POST request using the test client
            response = client.get(
                "/v1/auth/verify_user_token",
                headers={"Authorization": "Bearer dummyBearer"},
            )

            # Assert the response
            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data["message"] == "Access granted"


def test_verify_user_token_verification_error(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch(
            "app.v1.routes.verify_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = [
                None,
                "dummy_error",
            ]

            # Now, make the POST request using the test client
            response = client.get(
                "/v1/auth/verify_user_token",
                headers={"Authorization": "Bearer dummyBearer"},
            )

            # Assert the response
            assert response.status_code == 401
            json_data = response.get_json()
            assert json_data["error"] == "dummy_error"


def test_verify_user_token_unknown_exception(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch(
            "app.v1.routes.verify_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = None

            # Now, make the POST request using the test client
            response = client.get(
                "/v1/auth/verify_user_token",
                headers={"Authorization": "Bearer dummyBearer"},
            )

            # Assert the response
            assert response.status_code == 500
            json_data = response.get_json()
            assert (
                json_data["error"]
                == "'NoneType' object is not subscriptable"
            )


def test_verify_user_token_index_error(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch(
            "app.v1.routes.verify_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.side_effect = IndexError

            # Now, make the POST request using the test client
            response = client.get(
                "/v1/auth/verify_user_token",
                headers={"Authorization": "Bearer dummyBearer"},
            )

            # Assert the response
            assert response.status_code == 400
            json_data = response.get_json()
            assert json_data["error"] == "Token missing"


def test_get_csrf_token(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch(
            "app.v1.routes.generate_csrf"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = (
                "Dummy CSRF Token"
            )

            # Now, make the POST request using the test client
            response = client.get("/v1/auth/get-csrf-token")

            # Assert the response
            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data["csrfToken"] == "Dummy CSRF Token"


def test_refresh_token_successful_validation(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch.object(
            CSRFProtect, "protect", lambda x: None
        ), patch(
            "app.v1.routes.refresh_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = {
                "test_key": "test_value"
            }

            # Now, make the POST request using the test client
            response = client.post(
                "/v1/auth/refresh-token",
                headers={"Authorization": "Bearer dummyBearer"},
            )

            # Assert the response
            assert response.status_code == 200
            json_data = response.get_json()
            assert json_data["test_key"] == "test_value"


def test_refresh_token_unsuccessful_validation(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch.object(
            CSRFProtect, "protect", lambda x: None
        ), patch(
            "app.v1.routes.refresh_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = {
                "error": "error_value"
            }

            # Now, make the POST request using the test client
            response = client.post(
                "/v1/auth/refresh-token",
                headers={"Authorization": "Bearer dummyBearer"},
            )

            # Assert the response
            assert response.status_code == 400
            json_data = response.get_json()
            assert json_data["error"] == "error_value"


def test_refresh_token_missing_validation(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch.object(
            CSRFProtect, "protect", lambda x: None
        ), patch(
            "app.v1.routes.refresh_cognito_token"
        ) as mocked_verify_cognito_token:

            mocked_verify_cognito_token.return_value = {
                "error": "error_value"
            }

            # Now, make the POST request using the test client
            response = client.post(
                "/v1/auth/refresh-token",
                headers={"Authorization": "Bearer"},
            )

            # Assert the response
            assert response.status_code == 500
            json_data = response.get_json()
            assert json_data["error"] == "list index out of range"
