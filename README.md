# vuln-HTTP-Desync-Scanner
Identifies HTTP desynchronization vulnerabilities by sending crafted HTTP requests with ambiguous Content-Length and Transfer-Encoding headers and analyzing server responses for discrepancies and potential request smuggling. The crafted CL.TE probe is sent as a raw socket request, so the ambiguous headers reach the server as headers of an actual request. The verdict is differential: a baseline request is compared with a follow-up request sent after the probe, and the target is reported vulnerable only when the follow-up response body differs from the baseline or the follow-up is delayed against the baseline. Reflection of the probe's own bytes is never a verdict. Exit codes: 1 when vulnerable, 0 when a completed probe found no differential evidence, and 2 when no verdict was earned (invalid URL, timeout, or request failure). - Focused on Assess vulnerabilities in web applications by performing scans and providing detailed reports

## Install
`git clone https://github.com/ShadowStrikeHQ/vuln-http-desync-scanner`

## Usage
`./vuln-http-desync-scanner [params]`

## Parameters
- `-h`: Show help message and exit
- `-t`: No description provided
- `-v`: Enable verbose output. Verbose output logs status codes and response header names only, never header values or response bodies.
- `--insecure`: Disable TLS certificate verification for https targets. Verification is on by default.

## License
Copyright (c) ShadowStrikeHQ
