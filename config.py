import os


class Config:
    """Base configuration."""

    SECRET_KEY = (
        os.environ.get("SECRET_KEY") or "your-default-secret-key"
    )
    DEBUG = False
    TESTING = False
    # Add more shared config settings here


class DevelopmentConfig(Config):
    """Development configuration."""

    DEBUG = True
    ENV = "development"
    # Add development-specific settings here


class ProductionConfig(Config):
    """Production configuration."""

    DEBUG = False
    ENV = "production"
    # Add production-specific settings here


class TestingConfig(Config):
    DEBUG = False
    ENV = "testing"
