



import logging
from PIL import Image
from typing import Union
import pytesseract
import jwt

# Set the Tesseract 4.0 executable path
pytesseract.pytesseract.tesseract_cmd = '/usr/local/bin/tesseract'

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Create a stream handler
stream_handler = logging.StreamHandler()
stream_handler.setLevel(logging.INFO)

# Create a formatter and add it to the handler
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")

# Add the formatter to both handlers
stream_handler.setFormatter(formatter)

# Add the handlers to the logger
logger.addHandler(stream_handler)

# Check that the SECRET_KEY variable is defined in the global scope
if not "SECRET_KEY" in globals():
    raise NameError("The SECRET_KEY variable is not defined.")

def verify_auth(token, secret_key):
    # Check that the provided token is a valid JWT
    if not jwt.decode_verify(token, secret_key, algorithms=["HS256"]):
        return "The provided authentication token is invalid or has expired."

    # Verify that the user is authorized to access the OCR service
    try:
        payload = jwt.decode(token, secret_key, algorithms=["HS256"])
    except jwt.DecodeError:
        return "Failed to decode the authentication token."

    if not payload["authorized"]:
        return "You are not authorized to access the OCR service. Please contact the administrator for more information."

    # Return a success message if the token is valid and the user is authorized
    return "Authentication successful."
    
def validate_image_file(image_file: str) -> bool:
    """Validates that the provided file is a valid image file.

    Arguments:
        image_file: The path to the file to be validated.

    Returns:
        True if the file is a valid image file, or False if it is not.
    """
    try:
        # Try to open the file as an image file
        image = Image.open(image_file)
    except IOError:
        # Return False if the file is not a valid image file
        return False

    # Return True if the file is a valid image file
    return True                                       
                                           
def validate_lang(lang: str) -> bool:
    """Validates that the provided language code is supported by the pytesseract library.

    Arguments:
        lang: The language code to be validated.

    Returns:
        True if the language code is supported, or False if it is not.
    """
    # Get the list of supported languages
    supported_languages = pytesseract.get_available_languages()

    # Check if the provided language code is in the list of supported languages
    if lang in supported_languages:
        return True

    # Return False if the language code is not supported
    return False

def ocr(image_file: str, lang: str = "eng") -> Union[str, str]:
    """Performs optical character recognition (OCR) on the specified image file and returns the extracted text.

    Arguments:
        image_file: The path to the image file.
        lang: The language of the text in the image (default is "eng" for English).

    Returns:
        The OCR result as a string if the operation is successful, or an error message as a string if an error occurs.
    """
    # Validate that the provided file is a valid image file
    if not validate_image_file(image_file):
        return "The provided file is not a valid image file."

    # Check that the image file exists at the specified path
    if not os.path.isfile(image_file):
        return "The image file does not exist at the specified path."
      
    # Validate that the provided language code is supported by the pytesseract library
    if not validate_lang(lang):
        return "The provided language code is not supported by the OCR service."

    # Load the image file and perform OCR
    try:
        # Load the image file
        image = Image.open(image_file)

        # Run OCR on the image to extract the text
        # The --oem option specifies the OCR engine mode (3 = LSTM), and the --psm option specifies the page segmentation mode (6 = single-line)
        text = pytesseract.image_to_string(image, lang=lang, config="--oem 3 --psm 6")

    except (IOError, Image.DecompressionBombError) as error:
        # Handle the IOError and DecompressionBombError exceptions thrown by the Image.open function
        return "Failed to load the image file: {}".format(error)

    except pytesseract.TesseractError as error:
        # Handle the TesseractError exception thrown by the pytesseract.image_to_string function
        return "Failed to perform OCR on the image: {}".format(error)


    # Return the OCR result
    return text

