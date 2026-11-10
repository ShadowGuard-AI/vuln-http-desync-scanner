# vuln-HTTP-Desync-Scanner
Identifies HTTP desynchronization vulnerabilities by sending crafted HTTP requests with ambiguous Content-Length and Transfer-Encoding headers and analyzing server responses for discrepancies and potential request smuggling. The crafted CL.TE probe is sent as a raw socket request, so the ambiguous headers reach the server as headers of an actual request. The verdict is differential: a baseline request is compared with a follow-up request sent after the probe, and the target is reported vulnerable only when the follow-up response body differs from the baseline or the follow-up is delayed against the baseline. Reflection of the probe's own bytes is never a verdict. Exit codes: 1 when vulnerable, 0 when a completed probe found no differential evidence, and 2 when no verdict was earned (invalid URL, timeout, or request failure). - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowGuard-AI/vuln-http-desync-scanner`

No third party packages are required (standard library only).

## Usage
`python main.py <url> [params]`

Example: `python main.py http://127.0.0.1:8080/ -t 5 -v`

## Parameters
- `url` (positional, required): The URL to test. Its scheme must be http or https and its port, when present, must be a valid port number; an invalid URL prints INCONCLUSIVE and exits 2.
- `-h`: Show help message and exit
- `-t` / `--timeout`: Timeout in seconds (default: 10). It must be a positive integer; zero or negative values are rejected before any request is sent.
- `-v`: Enable verbose output. Verbose output logs status codes and response header names only, never header values or response bodies.
- `--insecure`: Disable TLS certificate verification for https targets. Verification is on by default.

## License
MIT License (see LICENSE).
