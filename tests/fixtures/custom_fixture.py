from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import BotoCoreError
from flask_wtf.csrf import CSRFProtect

from app import create_app


@pytest.fixture
def mock_prod_env_vars(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "production")


@pytest.fixture
def mock_dev_env_vars(monkeypatch):
    monkeypatch.setenv("FLASK_ENV", "development")


# Create the mock exception class
class MockBotocoreInvalidPasswordException(BotoCoreError):
    def __init__(self, message="Invalid Password."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "InvalidPasswordException",
                "Message": message,
            }
        }


# Create the mock exception class
class MockBotocoreUsernameExistsException(BotoCoreError):
    def __init__(self, message="User already exists."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "UsernameExistsException",
                "Message": message,
            }
        }


# Create the mock exception class
class MockBotocoreExpiredCodeException(BotoCoreError):
    def __init__(self, message="Token Expired."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "ExpiredCodeException",
                "Message": message,
            }
        }


# Create the mock exception class
class MockBotocoreCodeMismatchExceptionn(BotoCoreError):
    def __init__(self, message="Code Mismatched."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "CodeMismatchException",
                "Message": message,
            }
        }


# Create the mock exception class
class MockBotocoreNotAuthorizedException(BotoCoreError):
    def __init__(self, message="Not Authorized."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "NotAuthorizedException",
                "Message": message,
            }
        }


# Create the mock exception class
class MockBotocoreUserNotFoundException(BotoCoreError):
    def __init__(self, message="User Not Found."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "UserNotFoundException",
                "Message": message,
            }
        }


# Create the mock exception class
class MockBotocoreCodeMismatchException(BotoCoreError):
    def __init__(self, message="Code Mismatch."):
        super().__init__()
        self.response = {
            "Error": {
                "Code": "CodeMismatchException",
                "Message": message,
            }
        }


@pytest.fixture(autouse=True)
def client(mock_dev_env_vars):
    # Patch `boto3.client` before creating the app instance
    with patch("boto3.client") as mock_boto3:

        mocked_cognito_client = MagicMock()

        mocked_cognito_client.exceptions.UsernameExistsException = (
            MockBotocoreUsernameExistsException
        )
        mocked_cognito_client.exceptions.InvalidPasswordException = (
            MockBotocoreInvalidPasswordException
        )
        mocked_cognito_client.exceptions.ExpiredCodeException = (
            MockBotocoreExpiredCodeException
        )
        mocked_cognito_client.exceptions.CodeMismatchException = (
            MockBotocoreCodeMismatchExceptionn
        )
        mocked_cognito_client.exceptions.NotAuthorizedException = (
            MockBotocoreNotAuthorizedException
        )
        mocked_cognito_client.exceptions.UserNotFoundException = (
            MockBotocoreUserNotFoundException
        )
        mocked_cognito_client.exceptions.CodeMismatchException = (
            MockBotocoreCodeMismatchException
        )
        mocked_cognito_client.exceptions.ExpiredCodeException = (
            MockBotocoreExpiredCodeException
        )

        mock_boto3.return_value = mocked_cognito_client

        # Now you can create the app with the mocked client
        app = create_app()

        # Mock CSRF token validation to always succeed
        csrf = CSRFProtect(app)

        with app.test_client() as client:
            yield client, csrf
