import argparse
import logging
import socket
import ssl
import sys
import time
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Constants
DEFAULT_TIMEOUT = 10
# A follow-up response must be slower than the baseline by at least this
# many seconds before timing alone counts as differential evidence.
DELAY_THRESHOLD_SECONDS = 2.0


def setup_argparse():
    """Sets up the argument parser for the CLI."""
    parser = argparse.ArgumentParser(description="Identifies HTTP desynchronization vulnerabilities.")
    parser.add_argument("url", help="The URL to test (e.g., http://example.com)")
    parser.add_argument("-t", "--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Timeout in seconds (default: {DEFAULT_TIMEOUT})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--insecure", action="store_true",
                        help="Disable TLS certificate verification for https targets. Verification is on by default.")
    return parser


def raw_exchange(host, port, use_tls, insecure, raw_bytes, timeout):
    """
    Sends raw_bytes as the complete request over a raw socket and reads
    the response. Returns (status, header_names, body, elapsed_seconds).
    Raises OSError or ssl.SSLError on any transport failure.
    """
    context = None
    if use_tls:
        if insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        if use_tls:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                wrapped.sendall(raw_bytes)
                raw_response = _read_response(wrapped)
        else:
            sock.sendall(raw_bytes)
            raw_response = _read_response(sock)
    elapsed = time.monotonic() - started
    head, _, body = raw_response.partition(b"\r\n\r\n")
    lines = head.decode("latin1", errors="replace").split("\r\n")
    status = None
    if lines and lines[0].startswith("HTTP/"):
        parts = lines[0].split(" ")
        if len(parts) >= 2 and parts[1].isdigit():
            status = int(parts[1])
    header_names = []
    for line in lines[1:]:
        if ":" in line:
            header_names.append(line.split(":", 1)[0].strip())
    return status, header_names, body, elapsed


# Reads are capped at 64 KB and there is no chunked decoding here. A
# chunked response is only finished when the server closes or the socket
# times out, which inflates its elapsed time, so timing comparisons
# against a Content-Length baseline carry that bias.
def _read_response(sock):
    chunks = []
    total = 0
    while total < 65536:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            # A timeout mid response is treated as the end of it. Whatever
            # partial bytes arrived still get parsed for a status below.
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        joined = b"".join(chunks)
        head, _, body = joined.partition(b"\r\n\r\n")
        if head:
            for line in head.decode("latin1", errors="replace").split("\r\n")[1:]:
                if line.lower().startswith("content-length:"):
                    try:
                        if len(body) >= int(line.split(":", 1)[1].strip()):
                            return joined
                    except ValueError:
                        pass
    return b"".join(chunks)


def build_baseline_request(host_header, path):
    return (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode("utf-8")


def build_crafted_request(host_header, path):
    """
    Builds the CL.TE probe as one raw request: an ambiguous
    Content-Length and Transfer-Encoding header pair rides on the
    request itself, and the chunked body
    terminates at a zero chunk, leaving a smuggled request behind it.
    A server that honours Content-Length consumes the whole body; a
    server that honours Transfer-Encoding stops at the zero chunk and
    treats the smuggled request as the start of the next request.
    """
    smuggled = (
        "GET /desync-followup HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "\r\n"
    )
    chunked_body = "0\r\n\r\n" + smuggled
    content_length = len(chunked_body.encode("utf-8"))
    headers = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {content_length}\r\n"
        "Transfer-Encoding: chunked\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    return (headers + chunked_body).encode("utf-8")


def test_http_desync(url, timeout, verbose, insecure=False):
    """
    Tests for HTTP desynchronization using raw socket probes and a
    differential verdict: a baseline request is compared with a
    follow-up request sent after the crafted CL.TE probe. The target is
    reported vulnerable only when the follow-up response differs from
    the baseline in body, or is delayed past the threshold against the
    baseline. Reflection of the probe's own bytes is never a verdict.

    Returns:
        str: "vulnerable", "not_vulnerable", or "inconclusive" when no
             verdict was earned (invalid URL, timeout, or failure).
    """
    parsed_url = urlparse(url)
    host = parsed_url.hostname
    if not host:
        logging.error("Invalid URL: Hostname not found.")
        return "inconclusive"
    scheme = parsed_url.scheme
    if scheme not in ("http", "https"):
        logging.error("Invalid URL: Scheme must be http or https.")
        return "inconclusive"
    use_tls = scheme == "https"
    port = parsed_url.port or (443 if use_tls else 80)
    # The Host header is the raw netloc, port included when the URL has
    # one. I do not rebuild it from host and port, so what the operator
    # typed is what the server sees.
    host_header = parsed_url.netloc
    path = parsed_url.path or "/"
    if parsed_url.query:
        path = path + "?" + parsed_url.query

    if use_tls and insecure:
        logging.warning("TLS certificate verification disabled by the --insecure flag.")

    # Each of the three exchanges opens a fresh connection. Nothing on my
    # side carries over between them, so a changed follow up can only come
    # from state the server kept, which is exactly the desync signal.
    try:
        baseline_status, baseline_headers, baseline_body, baseline_time = raw_exchange(
            host, port, use_tls, insecure, build_baseline_request(host_header, path), timeout)
        if verbose:
            logging.info(f"Baseline response: status {baseline_status}, header names {baseline_headers}, {baseline_time:.3f}s")
        if baseline_status is None:
            logging.error("Baseline request received no readable HTTP response.")
            return "inconclusive"

        crafted_status, crafted_headers, _crafted_body, _crafted_time = raw_exchange(
            host, port, use_tls, insecure, build_crafted_request(host_header, path), timeout)
        if verbose:
            logging.info(f"Crafted CL.TE probe response: status {crafted_status}, header names {crafted_headers}")
        if crafted_status is None:
            logging.error("Crafted probe received no readable HTTP response.")
            return "inconclusive"

        follow_status, follow_headers, follow_body, follow_time = raw_exchange(
            host, port, use_tls, insecure, build_baseline_request(host_header, path), timeout)
        if verbose:
            logging.info(f"Follow-up response: status {follow_status}, header names {follow_headers}, {follow_time:.3f}s")
        if follow_status is None:
            logging.error("Follow-up request received no readable HTTP response.")
            return "inconclusive"
    except (OSError, ssl.SSLError) as e:
        logging.error(f"Request failed: {type(e).__name__}: {e}")
        return "inconclusive"

    body_changed = follow_body != baseline_body
    delayed = follow_time > baseline_time + DELAY_THRESHOLD_SECONDS
    if body_changed or delayed:
        reason = "follow-up response body differs from the baseline" if body_changed else "follow-up response was delayed against the baseline"
        logging.warning(f"Potential HTTP desynchronization vulnerability detected: {reason}.")
        return "vulnerable"

    logging.info("No HTTP desynchronization vulnerability detected: the follow-up response matched the baseline.")
    return "not_vulnerable"


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
    result = test_http_desync(args.url, args.timeout, args.verbose, args.insecure)
    if result == "vulnerable":
        print("VULNERABLE")  # Simple output for scripting
        sys.exit(1)  # Exit with an error code if vulnerable
    elif result == "not_vulnerable":
        print("NOT VULNERABLE")  # Simple output for scripting
        sys.exit(0)  # Exit with a success code if not vulnerable
    else:
        print("INCONCLUSIVE")  # No verdict was earned for this target
        sys.exit(2)


if __name__ == "__main__":
    main()
