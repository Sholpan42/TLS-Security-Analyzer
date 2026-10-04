# TLS Security Analyzer

**TLS Security Analyzer** is a desktop and command-line application for reviewing the TLS/HTTPS security posture of a public web endpoint. It combines protocol probes, certificate inspection, cipher analysis, HTTP security-header checks, evidence-based findings, and local reporting in one focused tool.

It is designed for defensive configuration reviews, learning, troubleshooting, and authorised security testing — not exploitation or full vulnerability assessment.

## Highlights

| Area | What the analyzer does |
| --- | --- |
| TLS protocols | Probes TLS 1.0, 1.1, 1.2, and 1.3 independently and records whether each version was actually negotiated. |
| Certificates | Inspects issuer, subject, Common Name, SANs, validity, public key, signature algorithm, hostname verification, and self-signed indicators. |
| Cipher suite | Describes the cipher negotiated for the current connection and flags common legacy algorithm markers. |
| HTTP controls | Checks eight common HTTPS response headers, using `HEAD` with a `GET` fallback where appropriate. |
| Findings | Produces structured findings with severity, evidence, and a concise remediation recommendation. |
| Reports | Saves JSON and PDF reports, plus a persistent local JSONL audit log. |
| Automation | Offers a CLI with machine-readable JSON output and a `--fail-on` security gate for CI/CD. |

## Interface

The CustomTkinter desktop workspace has four sections:

- **Dashboard** — recent scans and risk-level totals.
- **Scan** — run a scan and explore certificates, TLS probes, findings, and response headers.
- **Logs** — inspect the local structured audit trail.
- **About** — review the tool's checks, scope, and storage locations.

All scan output is selectable and copyable. Long certificate SAN lists and policy values wrap instead of being truncated.

## What is checked

### TLS protocol support

Each protocol is tested individually and reported as one of the following:

| Result | Meaning |
| --- | --- |
| `SUPPORTED` | The requested version was successfully negotiated. |
| `NOT_SUPPORTED` | The server reached the TLS layer but rejected or did not offer the requested version. |
| `PROBE_ERROR` | The result could not be determined reliably because of a client-side or connection error. |

The TLS 1.0 and TLS 1.1 probes use an isolated, relaxed OpenSSL context solely to determine whether an endpoint still accepts legacy clients. This does not lower the security of the normal scan connection.

Legacy TLS is evaluated in context:

- TLS 1.0/1.1 available **alongside TLS 1.2 or TLS 1.3** is recorded as an informational legacy-fallback finding.
- An endpoint with **no modern TLS support** is a Critical finding.

### Certificate and cipher analysis

The analyzer records:

- certificate issuer, Subject, Common Name, and SAN entries;
- certificate validity dates and remaining days;
- hostname and chain verification status;
- public-key type and size;
- signature algorithm and a self-signed heuristic;
- negotiated cipher name, TLS version, key size, encryption, key exchange, authentication, and strength.

The weak-cipher heuristic flags common legacy markers including RC4, 3DES, DES, NULL, MD5, and SHA-1. It assesses the cipher negotiated for the current connection; it is not exhaustive cipher-suite enumeration.

### HTTP security headers

The following headers are checked over HTTPS:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Content-Type-Options`
- `X-Frame-Options`
- `Referrer-Policy`
- `Permissions-Policy`
- `Cross-Origin-Opener-Policy`
- `Cross-Origin-Resource-Policy`

The application tries a `HEAD` request first and falls back to `GET` when a server rejects `HEAD` with `405` or `501`.

## Risk model

Successful scans produce findings with an ID, severity, evidence, and recommendation. The score is a **configuration-posture signal**, not a complete vulnerability rating for the organisation behind a domain.

| Severity | Score contribution |
| --- | ---: |
| Critical | 40 |
| High | 25 |
| Medium | 15 |
| Low | 5 |
| Info | 0 |

Scores are capped at 100. A Critical finding enforces a minimum score of 80, while a High finding enforces a minimum score of 50. Failed connections receive `N/A`, rather than a risk score, because the checks could not be completed.

The result represents one endpoint response from one scanning environment. CDN routing, load balancing, HTTP redirects, local OpenSSL policy, and the target's changing configuration can affect the observed result.

## Requirements

- Python 3.10 or newer
- Dependencies listed in [`requirements.txt`](requirements.txt)

```text
customtkinter
cryptography
python-dateutil
reportlab
```

## Installation

```powershell
git clone <your-repository-url>
cd TLS_Analyzer

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On macOS or Linux, activate the virtual environment with:

```bash
source .venv/bin/activate
```

## Usage

### Desktop application

```powershell
python .\TLS_Analyzer.py
```

Enter a domain such as `example.com`, then select **Scan**. The GUI creates local JSON/PDF reports and updates the Dashboard audit history after each scan.

### Command line

```powershell
python .\TLS_Analyzer.py example.com
```

Useful CLI options:

```powershell
# Print the complete scan result as JSON
python .\TLS_Analyzer.py example.com --json

# Save JSON and PDF reports
python .\TLS_Analyzer.py example.com --save-json --pdf

# Hide the human-readable summary line
python .\TLS_Analyzer.py example.com --quiet

# Fail a CI job when the result is High or Critical
python .\TLS_Analyzer.py example.com --fail-on high
```

### CLI exit codes

| Exit code | Meaning |
| --- | --- |
| `0` | Successful scan; no configured `--fail-on` threshold was reached. |
| `1` | Successful scan, but the risk level met or exceeded `--fail-on`. |
| `2` | The scan did not complete successfully, for example because of DNS, timeout, or TLS connection errors. |

## Reports and local storage

The application creates these local directories when needed:

```text
logs/
└── events.jsonl          # append-only structured scan events

reports/
├── report_<timestamp>.json
└── report_<timestamp>.pdf
```

These files are excluded from Git by default. They can contain target domains and scan metadata, so treat them as local assessment data.

## Testing

Run the offline unit test suite:

```powershell
python -m unittest discover -s .\tests -t . -v
```

Optional network-backed CLI integration tests are disabled by default. Enable them only when a network scan is appropriate:

```powershell
$env:RUN_NETWORK_TESTS="1"
python -m unittest discover -s .\tests -t . -v
```

The repository also includes a GitHub Actions workflow that installs dependencies, runs the tests, applies a CLI security gate, and uploads the scan-result artifact.

## Project structure

```text
TLS_Analyzer/
├── TLS_Analyzer.py          # shared scanner core, GUI, and CLI
├── requirements.txt         # Python dependencies
├── tests/                   # offline unit and optional integration tests
├── .github/workflows/       # automated test and security-gate workflow
├── logs/                    # local audit history (generated)
└── reports/                 # JSON/PDF reports (generated)
```

## Scope and limitations

TLS Security Analyzer is intentionally focused. It does not perform:

- port scanning or service enumeration;
- exploitation or penetration testing;
- complete cipher-suite enumeration;
- web-application vulnerability scanning;
- a full compliance audit;
- a complete assessment of an organisation or all of its infrastructure.

Use the findings to guide investigation and configuration review, not as a substitute for a formal security assessment.

## Authorised use

Only scan systems you own or have explicit permission to assess. The project is intended for defensive security testing, configuration validation, and educational use.
