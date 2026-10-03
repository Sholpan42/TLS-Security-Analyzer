# TLS Security Analyzer

TLS Security Analyzer is a desktop and command-line tool for assessing the TLS/HTTPS security posture of a web server.

The project focuses on practical TLS and HTTPS configuration checks rather than full-scale vulnerability scanning or penetration testing. It analyzes supported TLS versions, the server certificate, the negotiated cipher suite, HTTP security headers, and produces structured findings with evidence and remediation guidance.

## Features

- **TLS protocol probing** for TLS 1.0, 1.1, 1.2, and 1.3.
- Clear probe results: `SUPPORTED`, `NOT_SUPPORTED`, or `PROBE_ERROR`, with an explanation for each result.
- **TLS certificate analysis**, including:
  - certificate receipt;
  - hostname verification;
  - Subject and Common Name;
  - Subject Alternative Names (SAN);
  - expiration date and remaining validity;
  - public-key type and size;
  - certificate signature algorithm;
  - self-signed certificate heuristic.
- **Negotiated cipher-suite analysis** with encryption, authentication, key-exchange information, and weak/deprecated algorithm detection.
- **HTTP security-header checks** over HTTPS:
  - HSTS;
  - Content-Security-Policy;
  - X-Content-Type-Options;
  - X-Frame-Options;
  - Referrer-Policy;
  - Permissions-Policy;
  - Cross-Origin-Opener-Policy;
  - Cross-Origin-Resource-Policy.
- **Structured security findings** containing severity, description, evidence, and remediation.
- **Risk scoring** for successfully completed scans.
- **JSON and PDF reports**.
- **Local scan history and audit logs**.
- Desktop GUI with Dashboard, Scan, Logs, and About sections.
- Command-line interface suitable for automation and CI workflows.
- Configurable `--fail-on` exit behavior for CI/CD pipelines.

## Architecture

```text
┌─────────────────┐
│    GUI / CLI    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   TLS Scanner   │
└────────┬────────┘
         │
    ┌────┼────────────────────┐
    ▼    ▼                    ▼
┌──────┐ ┌──────────────┐ ┌──────────────┐
│ TLS  │ │ Certificate  │ │    HTTP      │
│ &    │ │   analysis   │ │   headers    │
│cipher│ │              │ │   analysis   │
└──┬───┘ └──────┬───────┘ └──────┬───────┘
   │             │                │
   └─────────────┼────────────────┘
                 ▼
        ┌─────────────────┐
        │ Risk / Finding  │
        │      Engine     │
        └────────┬────────┘
                 │
          ┌──────┴──────┐
          ▼             ▼
     JSON / PDF    Local history
                    & logs
```

The scanning logic is shared between the desktop application and the CLI, so both interfaces use the same core assessment workflow.

## Security Checks

### TLS protocol support

The analyzer probes TLS 1.3, TLS 1.2, TLS 1.1, and TLS 1.0 individually.

Each probe reports one of three states:

- `SUPPORTED` — the requested TLS version was successfully negotiated.
- `NOT_SUPPORTED` — the connection reached the TLS layer but the requested version was rejected or unavailable.
- `PROBE_ERROR` — the result could not be reliably determined because of a client-side limitation or connection error.

Legacy TLS 1.0 and TLS 1.1 probes use a relaxed OpenSSL security level specifically to determine whether the endpoint still accepts these legacy protocols.

### Certificate analysis

For a successfully established TLS connection, the analyzer records certificate information such as:

- issuer;
- subject;
- Common Name;
- SAN entries;
- validity period;
- remaining days before expiration;
- public-key type and size;
- certificate signature algorithm;
- hostname verification result;
- self-signed heuristic.

The self-signed check compares the certificate Subject and Issuer. This is treated as an indicator rather than independent cryptographic proof.

### Cipher suite

The analyzer evaluates the **cipher suite negotiated during the current TLS connection**.

It records:

- cipher-suite name;
- TLS version;
- key size;
- encryption information;
- authentication information;
- key-exchange information;
- strength classification;
- reason for a weak classification.

The weak-cipher check currently looks for legacy markers such as RC4, 3DES, DES, NULL, MD5, and SHA1.

This is a heuristic assessment of the negotiated cipher. The tool does **not** perform a complete enumeration of every cipher suite supported by the server.

### HTTP security headers

Security headers are checked over HTTPS.

The analyzer attempts a HEAD request first and falls back to GET when the server does not support HEAD with status 405 or 501.

The following headers are checked:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`

The absence of a header is classified according to the project's configured severity.

## Findings and Risk Scoring

Successful scans generate structured findings containing:

- **ID**
- **Severity**
- **Description**
- **Evidence**
- **Recommendation**

Examples include:

- legacy TLS versions enabled;
- modern TLS unavailable;
- TLS 1.3 unavailable;
- missing security headers;
- hostname verification failure;
- expired certificate;
- certificate expiring soon;
- apparent self-signed certificate;
- weak negotiated cipher suite.

Connectivity failures are represented as scan statuses rather than security findings. Consequently, failed scans receive a risk score of `N/A`.

### Severity weights

| Severity | Score contribution |
|---|---:|
| Critical | 40 |
| High | 25 |
| Medium | 15 |
| Low | 5 |
| Info | 0 |

The total score is capped at 100.

The resulting risk level is determined from the findings. Critical findings impose a minimum score of 80, while High findings impose a minimum score of 50.

## Scan Status

A scan can also terminate with a connection-related status:

| Status | Meaning |
|---|---|
| `SUCCESS` | Scan completed successfully |
| `DNS_ERROR` | DNS resolution failed |
| `TIMEOUT` | Connection timed out |
| `TLS_ERROR` | TLS handshake failed |
| `CONNECTION_ERROR` | Other connection-level failure |

A non-successful scan does not receive a security risk score.

## Desktop Application

The desktop application provides four main sections:

- **Dashboard** — scan statistics and recent activity.
- **Scan** — enter a domain and run an assessment.
- **Logs** — review the complete local audit log.
- **About** — overview of the checks, reports, scope, and limitations.

The Dashboard displays recent scan activity, while the full history remains available through the Logs section.

## Command-Line Usage

Run the desktop application:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py
```

Run a CLI scan:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com
```

Print the complete JSON result:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --json
```

Save a JSON report:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --save-json
```

Generate a PDF report:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --pdf
```

Save both JSON and PDF reports:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --pdf --save-json
```

Suppress the CLI summary:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --quiet
```

Use the scan as a CI/CD gate:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --fail-on high
```

The `--fail-on` option returns exit code `1` when the resulting risk level meets or exceeds the selected threshold. Failed scans return exit code `2`. A successful scan without a threshold violation returns exit code `0`.

## Reports and Audit History

Reports are stored in the local `reports/` directory.

The application can generate:

- JSON reports containing the complete scan result;
- PDF reports containing a formatted security summary.

Scan events are stored locally in:

```text
logs/events.jsonl
```

The application uses this file to provide persistent scan history and Dashboard statistics.

## Testing

Unit tests are designed to run offline:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s .\tests -t . -v
```

Network-dependent CLI integration tests can be enabled with:

```powershell
$env:RUN_NETWORK_TESTS="1"
```

If the repository contains the corresponding GitHub Actions workflow, the CI pipeline can run the tests and perform a network scan as part of the automated verification process.

## CI/CD

The CLI can be used as a security gate in automated pipelines.

The `--fail-on` option makes the scanner return a non-zero exit code when the configured risk threshold is reached, allowing CI/CD systems to fail a job based on the scan result.

Example:

```powershell
.\.venv\Scripts\python.exe .\TLS_Analyzer.py example.com --fail-on high
```

## Limitations

TLS Security Analyzer is intentionally scoped as a **TLS/HTTPS posture assessment tool**.

It does not provide:

- port scanning;
- service enumeration;
- exploitation;
- penetration testing;
- vulnerability exploitation;
- complete cipher-suite enumeration;
- comprehensive application security testing;
- full web-application vulnerability scanning.

Results represent the security posture observed from a single scanning client and should not be treated as a complete security assessment of the target environment.

TLS probing and cipher classification are also affected by the capabilities and security policies of the local Python/OpenSSL environment.

## Authorization

Only scan systems that you own or are explicitly authorized to assess.

The tool is intended for defensive security assessment, configuration verification, troubleshooting, and authorized security testing.
