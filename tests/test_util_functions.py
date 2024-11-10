import base64
from unittest.mock import MagicMock, patch

import pytest
import requests
from jwt import ExpiredSignatureError, InvalidTokenError

from app.v1.routes import (
    get_cognito_pem,
    get_jwk,
    handle_csrf_error,
    refresh_cognito_token,
    verify_cognito_token,
)
# fmt: off
from tests.fixtures.custom_fixture import client  # noqa: F401
from tests.fixtures.custom_fixture import mock_dev_env_vars  # noqa: F401

# fmt: on


def test_get_jwk_success(client):  # noqa: F811

    client, _ = client

    # Access the app instance from the client
    app = client.application

    # Mocking requests.get
    with patch("requests.get") as mock_get:
        # Create a mock response
        mock_response = MagicMock()
        mock_response.raise_for_status = (
            MagicMock()
        )  # No exception should be raised
        mock_response.json.return_value = {
            "keys": ["mock_key_1", "mock_key_2"]
        }  # Mock the JSON data returned
        mock_get.return_value = mock_response  # Return the mock response when requests.get is called

        # Mock the `current_app.jwks_url` within the app context
        with app.app_context():
            # Directly mock `current_app.jwks_url`
            app.jwks_url = "http://mockurl.com"

            # Call the function you're testing
            jwk = get_jwk()  # This will use the mocked `app.jwks_url`

        # Check if requests.get was called with the correct URL
        mock_get.assert_called_once_with("http://mockurl.com")

        # Verify the returned data
        assert jwk == {"keys": ["mock_key_1", "mock_key_2"]}


def test_get_jwk_failure(client):  # noqa: F811

    client, _ = client

    # Access the app instance from the client
    app = client.application

    # Test the case where the request fails (e.g., status code 404)
    with patch("requests.get") as mock_get:
        # Create a mock response that raises an HTTPError
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = (
            requests.exceptions.HTTPError("Not Found")
        )
        mock_get.return_value = mock_response

        # Ensure that the exception is raised properly
        with app.app_context():
            # Mock the `current_app.jwks_url` within the app context
            app.jwks_url = "http://mockurl.com"

            # Ensure the exception is raised
            with pytest.raises(requests.exceptions.HTTPError):
                get_jwk()


def test_get_cognito_pem_success():
    # Sample JWK key with e and n values (base64url encoded)
    jwk_key = {
        "e": "AQAB",  # A simple public exponent (base64url encoded)
        "n": "sXl9A8lUJ1l8HGrT4X9qPbYZAKuI0bqPRYmI7P7dOM8NjE0g7bG5dYOWeNGo-IPrds5WQ-lhU9vVog65J2nRtDtO8CmVg2mrD5H2nYx2m3gsjeZobpU38wNOYJlmbAlx74jJBYj5Plv9b5ZYWhwD3ge-Ashvhpm97aYZXu3AljYWGzA==",
    }

    # Mock the components involved in creating the public key
    with patch(
        "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicNumbers"
    ) as mock_rsa_numbers, patch(
        "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey"
    ), patch(
        "cryptography.hazmat.primitives.asymmetric.rsa.RSAPublicKey.public_bytes"
    ) as mock_public_bytes:

        # Mock the `public_bytes` method to return a PEM string (mocked output)
        mock_public_bytes.return_value = b"-----BEGIN PUBLIC KEY-----\nMocked PEM Key\n-----END PUBLIC KEY-----\n"

        # Call the function you're testing
        get_cognito_pem(jwk_key)

        # Check that the public key was created correctly
        mock_rsa_numbers.assert_called_once_with(
            int.from_bytes(
                base64.urlsafe_b64decode(jwk_key["e"] + "=="), "big"
            ),
            int.from_bytes(
                base64.urlsafe_b64decode(jwk_key["n"] + "=="), "big"
            ),
        )


def test_csrf_error(client):  # noqa: F811
    client, _ = client

    # Access the app instance from the client
    app = client.application

    with app.app_context():
        response = handle_csrf_error("testing error")

        assert response[1] == 400
        assert (
            response[0].get_json()["error"]
            == "Invalid CSRF token testing error"
        )


def test_refresh_cognito_token_method(client):  # noqa: F811

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():
        with patch.object(app.cognito_client, "initiate_auth"):
            refresh_cognito_token(token)


def test_refresh_cognito_token_unknown_exception(
    client,  # noqa: F811
):

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():
        with patch.object(
            app.cognito_client, "initiate_auth"
        ) as mocked_initiate_auth:
            mocked_initiate_auth.side_effect = Exception(
                "Dummy Exception"
            )
            refresh_cognito_token(token)


def test_verify_cognito_token_successful_validation(
    client,  # noqa: F811
):

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():
        with patch(
            "app.v1.routes.get_unverified_header"
        ) as mocked_get_verified_header, patch(
            "app.v1.routes.get_jwk"
        ) as mocked_get_jwk, patch(
            "app.v1.routes.get_cognito_pem"
        ) as mocked_get_cognito_pem, patch(
            "app.v1.routes.decode"
        ) as mocked_jwt_decode:

            mocked_get_verified_header.return_value = {
                "kid": "XXXXXXXXXX"
            }
            mocked_get_jwk.return_value = {
                "keys": [
                    {
                        "kid": "XXXXXXXXXX",
                        "e": "XXXXXXXXXX",
                        "n": "XXXXXXXXXX",
                        "kty": "XXXXXXXXXX",
                        "alg": "XXXXXXXXXX",
                        "use": "XXXXXXXXXX",
                    }
                ]
            }
            mocked_get_cognito_pem.return_value = "XXXXXXXXXX"
            mocked_jwt_decode.return_value = {
                "username": "XXXXXXXXXX"
            }

            # Clear the cache before running the test
            verify_cognito_token.cache_clear()
            result = verify_cognito_token(token)

            assert result[0]["username"] == "XXXXXXXXXX"
            assert result[1] == "success"


def test_verify_cognito_token_header_missing_exception(
    client,  # noqa: F811
):

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():

        with patch(
            "app.v1.routes.get_unverified_header"
        ) as mocked_get_verified_header:

            mocked_get_verified_header.return_value = None

            # Clear the cache before running the test
            verify_cognito_token.cache_clear()
            result = verify_cognito_token(token)

            assert result[1] == 'Token header missing "kid"'


def test_verify_cognito_token_payload_decoding_error(
    client,  # noqa: F811
):

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():
        with patch(
            "app.v1.routes.get_unverified_header"
        ) as mocked_get_verified_header, patch(
            "app.v1.routes.get_jwk"
        ) as mocked_get_jwk, patch(
            "app.v1.routes.get_cognito_pem"
        ) as mocked_get_cognito_pem:

            mocked_get_verified_header.return_value = {
                "kid": "XXXXXXXXXX"
            }
            mocked_get_jwk.return_value = {
                "keys": [
                    {
                        "kid": "XXXXXXXXXX",
                        "e": "XXXXXXXXXX",
                        "n": "XXXXXXXXXX",
                        "kty": "XXXXXXXXXX",
                        "alg": "XXXXXXXXXX",
                        "use": "XXXXXXXXXX",
                    }
                ]
            }
            mocked_get_cognito_pem.return_value = None

            # Clear the cache before running the test
            verify_cognito_token.cache_clear()
            result = verify_cognito_token(token)

            assert result[1] == "Unable to find appropriate key"


def test_verify_cognito_token_invalid_token_error(
    client,  # noqa: F811
):

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():
        with patch(
            "app.v1.routes.decode",
            side_effect=InvalidTokenError("Invalid Token Error"),
        ), patch(
            "app.v1.routes.get_unverified_header"
        ) as mocked_get_verified_header, patch(
            "app.v1.routes.get_jwk"
        ) as mocked_get_jwk, patch(
            "app.v1.routes.get_cognito_pem"
        ) as mocked_get_cognito_pem:

            mocked_get_verified_header.return_value = {
                "kid": "XXXXXXXXXX"
            }
            mocked_get_jwk.return_value = {
                "keys": [
                    {
                        "kid": "XXXXXXXXXX",
                        "e": "XXXXXXXXXX",
                        "n": "XXXXXXXXXX",
                        "kty": "XXXXXXXXXX",
                        "alg": "XXXXXXXXXX",
                        "use": "XXXXXXXXXX",
                    }
                ]
            }
            mocked_get_cognito_pem.return_value = "XXXXXXXXXX"

            # Clear the cache before running the test
            verify_cognito_token.cache_clear()
            result = verify_cognito_token(token)

            assert result[0] is None
            assert result[1] == "Invalid Token Error"


def test_verify_cognito_token_expired_signature_error(
    client,  # noqa: F811
):

    token = "dummy token"
    client, _ = client
    # Access the app instance from the client
    app = client.application

    with app.app_context():
        with patch(
            "app.v1.routes.decode",
            side_effect=ExpiredSignatureError(
                "Expired Signature Error"
            ),
        ), patch(
            "app.v1.routes.get_unverified_header"
        ) as mocked_get_verified_header, patch(
            "app.v1.routes.get_jwk"
        ) as mocked_get_jwk, patch(
            "app.v1.routes.get_cognito_pem"
        ) as mocked_get_cognito_pem:

            mocked_get_verified_header.return_value = {
                "kid": "XXXXXXXXXX"
            }
            mocked_get_jwk.return_value = {
                "keys": [
                    {
                        "kid": "XXXXXXXXXX",
                        "e": "XXXXXXXXXX",
                        "n": "XXXXXXXXXX",
                        "kty": "XXXXXXXXXX",
                        "alg": "XXXXXXXXXX",
                        "use": "XXXXXXXXXX",
                    }
                ]
            }
            mocked_get_cognito_pem.return_value = "XXXXXXXXXX"

            # Clear the cache before running the test
            verify_cognito_token.cache_clear()
            result = verify_cognito_token(token)

            assert result[0] is None
            assert result[1] == "Expired Signature Error"
