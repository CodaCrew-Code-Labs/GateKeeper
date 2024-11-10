import base64
from functools import lru_cache

import requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Blueprint, current_app, jsonify, request
from flask_wtf.csrf import CSRFError, generate_csrf
from jwt import (
    ExpiredSignatureError,
    InvalidTokenError,
    decode,
    get_unverified_header,
)

# Define a Blueprint for the routes
main_routes = Blueprint("v1", __name__)


@main_routes.route("/", methods=["GET"])
def hello():
    """
    A greeting endpoint for Version 1.
    ---
    responses:
        200:
            description: A greeting message
    """

    # Logger
    # current_app.logger.info("Data received: %s", "Testing Tested")

    return (
        jsonify(
            {
                "message": "This is version 1 of the API",
                "status": "SUCCESS",
            }
        ),
        200,
    )


# Sign-Up Route
@main_routes.route("/auth/signup", methods=["POST"])
def sign_up():
    data = request.json
    password = data.get("password")
    email = data.get("email")
    app_tag = data.get("app_tag")

    try:

        # Sign up a new user in Cognito
        response = current_app.cognito_client.sign_up(
            ClientId=current_app.client_id,
            Username=email,
            Password=password,
            UserAttributes=[
                {"Name": "email", "Value": email},
                {"Name": "custom:app_tag", "Value": app_tag},
            ],
        )

        return (
            jsonify(
                {
                    "message": "User registered successfully. Check your email to confirm the account.",
                    "user_sub": response["UserSub"],
                }
            ),
            200,
        )
    except (
        current_app.cognito_client.exceptions.UsernameExistsException
    ):
        return jsonify({"error": "User already exists."}), 409
    except (
        current_app.cognito_client.exceptions.InvalidPasswordException
    ):
        return (
            jsonify(
                {
                    "error": "Password does not meet the policy requirements."
                }
            ),
            400,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Confirm Sign-Up Route
@main_routes.route("/auth/confirm-signup", methods=["POST"])
def confirm_sign_up():
    data = request.json
    username = data.get("email")
    confirmation_code = data.get("confirmation_code")

    try:
        # Confirm the user's sign-up with the confirmation code
        current_app.cognito_client.confirm_sign_up(
            ClientId=current_app.client_id,
            Username=username,
            ConfirmationCode=confirmation_code,
        )
        return (
            jsonify({"message": "User confirmed successfully."}),
            200,
        )
    except (
        current_app.cognito_client.exceptions.CodeMismatchException
    ):
        return jsonify({"error": "Invalid confirmation code."}), 400
    except current_app.cognito_client.exceptions.ExpiredCodeException:
        return (
            jsonify({"error": "Confirmation code has expired."}),
            400,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Email/Password Sign-In
@main_routes.route("/auth/signin", methods=["POST"])
def sign_in():
    data = request.json
    username = data.get("email")
    password = data.get("password")
    client_app_tag = data.get("app_tag")

    try:
        # Step 1: Authenticate the user with initiate_auth
        response = current_app.cognito_client.initiate_auth(
            ClientId=current_app.client_id,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": username,
                "PASSWORD": password,
            },
        )

        # Step 2: Retrieve the ID token
        access_token = response["AuthenticationResult"]["AccessToken"]

        # Step 3: Fetch user details using the ID token
        user_details = current_app.cognito_client.get_user(
            AccessToken=access_token
        )

        # Step 4: Extract custom tag attribute
        user_app_tag = None
        for attr in user_details["UserAttributes"]:
            if (
                attr["Name"] == "custom:app_tag"
            ):  # Assuming 'custom:app_tag' is the tag attribute
                user_app_tag = attr["Value"]
                break

        # Step 5: Validate if the tag matches the required tag
        if user_app_tag == client_app_tag:
            return (
                jsonify(
                    {
                        "access_token": response[
                            "AuthenticationResult"
                        ]["AccessToken"],
                        "id_token": response["AuthenticationResult"][
                            "IdToken"
                        ],
                        "refresh_token": response[
                            "AuthenticationResult"
                        ]["RefreshToken"],
                    }
                ),
                200,
            )
        else:
            return (
                jsonify(
                    {"error": "User not authorized to use this App"}
                ),
                403,
            )

    except (
        current_app.cognito_client.exceptions.NotAuthorizedException
    ):
        return jsonify({"error": "Invalid credentials."}), 401
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Forgot Password - Step 1: Initiate Password Reset
@main_routes.route("/auth/forgot-password", methods=["POST"])
def forgot_password():
    data = request.json
    username = data.get("email")

    try:
        # Trigger forgot password request
        current_app.cognito_client.forgot_password(
            ClientId=current_app.client_id, Username=username
        )
        return (
            jsonify(
                {"message": "Password reset code sent to email."}
            ),
            200,
        )
    except (
        current_app.cognito_client.exceptions.UserNotFoundException
    ):
        return jsonify({"error": "User does not exist."}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Forgot Password - Step 2: Confirm Password Reset
@main_routes.route("/auth/confirm-forgot-password", methods=["POST"])
def confirm_forgot_password():
    data = request.json
    username = data.get("email")
    confirmation_code = data.get("confirmation_code")
    new_password = data.get("new_password")

    try:
        # Confirm password reset with confirmation code
        current_app.cognito_client.confirm_forgot_password(
            ClientId=current_app.client_id,
            Username=username,
            ConfirmationCode=confirmation_code,
            Password=new_password,
        )
        return (
            jsonify(
                {"message": "Password has been reset successfully."}
            ),
            200,
        )
    except (
        current_app.cognito_client.exceptions.CodeMismatchException
    ):
        return jsonify({"error": "Invalid confirmation code."}), 400
    except current_app.cognito_client.exceptions.ExpiredCodeException:
        return (
            jsonify({"error": "Confirmation code has expired."}),
            400,
        )
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# The JWKS URL to fetch public keys
# Fetch the JWKS (public keys) from Cognito
def get_jwk():
    response = requests.get(current_app.jwks_url)
    response.raise_for_status()  # Raise an error if the response is not successful
    return response.json()


def get_cognito_pem(jwk_key):
    """Converts a JWK key to a PEM-format public key"""
    # Decode 'e' and 'n' from base64url
    e = int.from_bytes(
        base64.urlsafe_b64decode(jwk_key["e"] + "=="), "big"
    )
    n = int.from_bytes(
        base64.urlsafe_b64decode(jwk_key["n"] + "=="), "big"
    )

    public_key = rsa.RSAPublicNumbers(e, n).public_key(
        backend=default_backend()
    )

    # Serialize to PEM format and decode bytes to string
    pem_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode(
        "utf-8"
    )  # Decode bytes to a UTF-8 string
    return pem_key


# Validate the JWT token using pyjwt and Cognito's public keys
@lru_cache(maxsize=128)
def verify_cognito_token(token):
    try:
        # Decode the unverified JWT header to get the kid (key ID)
        unverified_header = get_unverified_header(token)

        if (
            unverified_header is None
            or "kid" not in unverified_header
        ):
            raise Exception('Token header missing "kid"')

        # Get the JWKS keys
        jwks = get_jwk()

        # Parse the JWKs
        keys = jwks["keys"]

        # Decode header of the token to find the key id (kid)
        kid = unverified_header["kid"]

        # Find the corresponding JWK
        rsa_key = next(
            (key for key in keys if key["kid"] == kid), None
        )

        # Convert JWK to PEM
        pem_key = get_cognito_pem(rsa_key)

        if pem_key:
            # Decode the token with the found public key
            payload = decode(
                token,
                pem_key,
                algorithms=["RS256"],
                audience=current_app.client_id,
            )

            return (payload, "success")
        else:
            raise Exception("Unable to find appropriate key")
    except ExpiredSignatureError as e:
        print("Token has expired")
        return (None, str(e))
    except InvalidTokenError as e:
        print("Invalid Token")
        return (None, str(e))
    except Exception as e:
        print(f"Token validation failed: {e}")
        return (None, str(e))


@main_routes.route("/auth/verify_user_token", methods=["GET"])
def protected():
    try:

        # Get the token from Authorization header
        token = request.headers.get("Authorization").split()[1]

        # Validate the token
        verified_token = verify_cognito_token(token)

        if verified_token[0]:
            # Token is valid, allow access
            return (
                jsonify(
                    {
                        "message": "Access granted",
                        "user": verified_token,
                    }
                ),
                200,
            )
        else:
            return jsonify({"error": verified_token[1]}), 401
    except IndexError:
        return jsonify({"error": "Token missing"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def refresh_cognito_token(refresh_token):
    """
    Uses Cognito's REFRESH_TOKEN_AUTH flow to refresh the access token.
    """
    try:
        response = current_app.cognito_client.initiate_auth(
            ClientId=current_app.client_id,
            AuthFlow="REFRESH_TOKEN_AUTH",
            AuthParameters={"REFRESH_TOKEN": refresh_token},
        )

        # Extract new tokens from the response
        new_access_token = response["AuthenticationResult"][
            "AccessToken"
        ]
        new_id_token = response["AuthenticationResult"]["IdToken"]

        return {
            "access_token": new_access_token,
            "id_token": new_id_token,
        }

    except Exception as e:
        # Handle exceptions
        return {"error": str(e)}, 400


@main_routes.route("/auth/refresh-token", methods=["POST"])
def refresh_token_route():
    try:
        # Get the refresh token from request body or headers
        refresh_token = request.headers.get("Authorization").split()[
            1
        ]

        # Refresh the token
        tokens = refresh_cognito_token(refresh_token)

        if "error" in tokens:
            return jsonify(tokens), 400
        else:
            return jsonify(tokens), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@main_routes.route("/auth/get-csrf-token", methods=["GET"])
def get_csrf_token():
    token = generate_csrf()
    return jsonify({"csrfToken": token}), 200


# Handle CSRF error
@main_routes.errorhandler(CSRFError)
def handle_csrf_error(e):
    return jsonify({"error": "Invalid CSRF token " + str(e)}), 400
