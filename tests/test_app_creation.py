import logging
from unittest.mock import mock_open, patch

from app import configure_logging, create_app
# fmt: off
from tests.fixtures.custom_fixture import client  # noqa: F401
from tests.fixtures.custom_fixture import mock_dev_env_vars  # noqa: F401
from tests.fixtures.custom_fixture import mock_prod_env_vars  # noqa: F401

# fmt: on


def test_create_app_in_production_mode(
    mock_prod_env_vars,  # noqa: F811
):

    # Create the app with the mocked db instance
    app = create_app()

    # Check if the database URL is set correctly
    assert app.config["ENV"] == "production"

    # Check that the app is created successfully
    assert app is not None

    # Check that the logging is set up
    assert app.logger.level == logging.INFO


def test_create_app_in_development_mode(
    mock_dev_env_vars,  # noqa: F811
):

    app = create_app()

    # Check if the database URL is set correctly
    assert app.config["ENV"] == "development"


def test_hello_route(client):  # noqa: F811

    client, _ = client

    # Make a GET request to the /v1/ endpoint
    response = client.get("/v1/")

    # Assert that the response is successful
    assert (
        response.status_code == 200
    )  # Check that it returns a 200 OK

    # Extract the JSON data from the response
    json_data = response.get_json()

    # Check the expected response message
    assert json_data["message"] == "This is version 1 of the API"
    assert json_data["status"] == "SUCCESS"


def test_configure_logging():
    with patch("app.os.path.exists") as mock_exists, patch(
        "app.os.makedirs"
    ) as mock_makedirs, patch("builtins.open", mock_open()), patch(
        "app.logging.FileHandler"
    ):

        # Simulate that the directory does not exist
        mock_exists.return_value = False

        # Call the function
        configure_logging("test_logs")

        # Check that the directory existence was checked and created
        mock_exists.assert_called_once_with("test_logs")
        mock_makedirs.assert_called_once_with("test_logs")
