import logging
import os
from logging.handlers import RotatingFileHandler

import boto3
from dotenv import load_dotenv
from flask import Flask
from flask_cors import CORS
from flask_wtf.csrf import CSRFProtect

from app.v1.routes import main_routes as v1
from config import DevelopmentConfig, ProductionConfig

load_dotenv()

# Define the CSRFProtect object here, but don't initialize it yet
csrf = CSRFProtect()


def configure_logging(log_dir="logs"):
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    file_handler = RotatingFileHandler(
        os.path.join(log_dir, "app.log"),
        maxBytes=10240,
        backupCount=10,
    )
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s: %(message)s"
    )
    file_handler.setFormatter(formatter)
    return file_handler


def create_app(config_class=None):
    app = Flask(__name__)
    CORS(app)
    csrf.init_app(app)

    # Determine the environment and load the appropriate config
    if config_class is None:
        if os.environ.get("FLASK_ENV") == "production":
            config_class = ProductionConfig
        else:
            config_class = DevelopmentConfig

    app.config.from_object(config_class)

    # AWS Cognito configuration
    aws_region = os.environ.get("AWS_REGION")
    client_id = os.environ.get("GATEKEEPER_CLIENT_ID")
    userpool_id = os.environ.get("USER_POOL_ID")
    jwks_url = os.environ.get("JWKS_URL")

    # Cognito client
    cognito_client = boto3.client(
        "cognito-idp", region_name=aws_region
    )

    app.cognito_client = cognito_client
    app.client_id = client_id
    app.userpool_id = userpool_id
    app.jwks_url = jwks_url

    # Set up logging
    file_handler = configure_logging()
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)

    # Register Blueprints
    app.register_blueprint(v1, url_prefix="/v1")

    # Print the configuration values
    app.logger.info(f"ENV: {app.config['ENV']}")

    return app
