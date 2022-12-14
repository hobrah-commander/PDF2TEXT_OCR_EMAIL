import jwt
import logging
import datetime

# Create a global dictionary to store the cached JWT payloads
jwt_payloads = {}

def verify_jwt(token, secret_key, algorithms):
    try:
        # Use the jwt.decode_verify() function's options parameter to specify the list of supported algorithms
        options = {"algorithms": algorithms}

        # Check if the JWT payload is already cached
        if token in jwt_payloads:
            # Return the cached payload if it exists
            return jwt_payloads[token]
        else:
            # Decode the JWT and cache the payload if it is not cached
            payload = jwt.decode_verify(token, secret_key, options=options)
            jwt_payloads[token] = payload
            return payload
    except (jwt.ExpiredSignatureError, jwt.InvalidAlgorithmError, jwt.DecodeError, jwt.InvalidTokenError) as error:
        return None
        
def is_token_expired(token, secret_key, algorithms):
    # Verify that the provided token is a valid JWT and decode it
    payload = verify_jwt(token, secret_key, algorithms)
    if payload is None:
        # Return True if the token is invalid, as it is effectively expired
        return True

    # Check if the token has expired
    if "exp" in payload:
        # Use the datetime module to convert the expiration timestamp to a datetime object
        expiration_timestamp = datetime.datetime.fromtimestamp(payload["exp"])
        # Use the datetime.datetime.utcnow() method to get the current UTC time
        now = datetime.datetime.utcnow()
        # Compare the current time to the expiration timestamp to check if the token has expired
        if now > expiration_timestamp:
            return True

    # Return False if the token is valid and not expired
    return False
    
def is_user_authorized(token, secret_key, algorithms):
    # Verify that the provided token is a valid JWT and decode it
    payload = verify_jwt(token, secret_key, algorithms)
    if payload is None:
        # Return False if the token is invalid
        return False

    # Verify that the user is authorized to access the OCR service
    if not payload["authorized"]:
        return False
    else:
        return True    

def verify_auth(token, secret_key, algorithms):
    # Set up the logger
    logger = logging.getLogger(__name__)

    # Use basicConfig() to set the logger's formatting options
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")

    # Use the with statement to handle the stream handler for the logger
    with logging.StreamHandler() as handler:
        logger.addHandler(handler)

    # Verify that the provided token is a valid JWT and decode it
    payload = verify_jwt(token, secret_key, algorithms)
    if payload is None:
        logger.error("Failed to verify the authentication token.")
        return "Failed to verify the authentication token. Please check that the token is a valid JWT and try again."

    # Check if the token has expired
    if is_token_expired(token, secret_key, algorithms):
        logger.warning("The provided authentication token has expired.")
        return "The provided authentication token has expired. Please request a new token and try again."

    # Verify that the user is authorized to access the OCR service
    if not is_user_authorized(token, secret_key, algorithms):
        logger.warning("The user is not authorized to access the OCR service.")
        return "The user is not authorized to access the OCR service. Please contact the service administrator for more information."

    # Verify that the JWT payload contains a valid user ID
    if "sub" not in payload or not isinstance(payload["sub"], str):
        return "The authentication token is missing the user ID or the user ID is invalid."

    # Verify that the JWT payload contains valid timestamps
    if "iat" not in payload or not isinstance(payload["iat"], int):
        return "The authentication token is missing the issued-at timestamp or the timestamp is invalid."
    if "exp" not in payload or not isinstance(payload["exp"], int):
        return "The authentication token is missing the expiration timestamp or the timestamp is invalid."

    # Verify that the user is authorized to access the OCR service
    if not payload["authorized"]:
        return "You are not authorized to access the OCR service. Please contact the administrator for more information."
    else:
        logger.info("User is authorized to access the OCR service.")

    # Return a success message if the token is valid and the user is authorized
    return "Authentication successful
