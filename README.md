# AI Code Security Scanner

A lightweight Python security scanner with both a command-line interface and a local Flask web interface. It scans AI-generated code and text files for common security risks before they are committed, shared, or deployed.

AI coding assistants can speed up development, but generated files may accidentally include secrets, unsafe Python patterns, or sensitive prompt-related notes. This scanner adds a simple review step for students, hobby projects, and small teams.

## Features

- Scan one file or a whole directory recursively.
- Scan a public GitHub repository by URL.
- Paste code or upload files in a local browser UI.
- Supports `.py`, `.json`, `.env`, `.txt`, and `.md` files.
- Detects likely hardcoded secrets, risky Python functions, and prompt leak indicators.
- Prints a readable terminal report.
- Exports downloadable JSON and text reports.
- Visualizes exported JSON reports with a local dashboard.
- Uses a simple file-level risk score: Low, Medium, or High.
- Keeps uploaded browser content in memory instead of saving source files.

## Installation

Clone the repository and install dependencies:

```bash
pip install -r requirements.txt
```

Flask powers the optional local web interface. Pytest is used for tests.

## CLI Usage

Scan the current directory:

```bash
python main.py scan .
```

Scan a single file:

```bash
python main.py scan app.py
```

Write a JSON report:

```bash
python main.py scan . --json report.json
```

Print only a compact summary:

```bash
python main.py scan . --quiet
```

Scan a public GitHub repository:

```bash
python main.py scan-repo https://github.com/owner/repo
```

Scan a specific branch:

```bash
python main.py scan-repo https://github.com/owner/repo/tree/main
```

Write a JSON report for a GitHub repository:

```bash
python main.py scan-repo https://github.com/owner/repo --json report.json
```

## Web Usage

Start the local Flask app:

```bash
python web_app.py
```

Open the app in your browser:

```text
http://127.0.0.1:5000
```

From the web interface, you can paste code, upload one or more supported files, enter a public GitHub repository URL, review findings, and download either a JSON or plain-text report.

You can also upload a previously exported `report.json` from the homepage to reopen the dashboard without rescanning code.

## Sample Output

```text
AI Code Security Scanner
=========================
Target: .
Files scanned: 4
Findings: 3

Findings
--------

app.py (score: 8, risk: Medium)
  Line 7: [High] hardcoded_secret - Credential assignment
    Potential hardcoded credential assignment found.
  Line 12: [Medium] risky_function - subprocess.run(shell=True)
    subprocess.run() with shell=True can allow command injection.

notes.md (score: 2, risk: Low)
  Line 3: [Medium] prompt_leak - Prompt leak indicator
    Prompt leak indicator found: system prompt.
```

## What It Detects

Hardcoded secret indicators:

- OpenAI-style API keys
- AWS-style access keys
- Generic bearer tokens
- Password, API key, secret, and token assignments
- Email addresses

Risky Python functions:

- `eval(`
- `exec(`
- `pickle.load(`
- `os.system(`
- `subprocess.Popen(`
- `subprocess.run(..., shell=True)`

Prompt leak indicators in comments or obvious text content:

- `user asked`
- `internal prompt`
- `system prompt`
- `do not share`
- `confidential`
- `secret`
- `token`

## Project Structure

```text
ai-code-security-scanner/
|-- main.py
|-- web_app.py
|-- scanner/
|   |-- engine.py
|   |-- secrets.py
|   |-- risks.py
|   |-- prompt_leak.py
|   `-- scoring.py
|-- templates/
|   |-- index.html
|   `-- results.html
|-- static/
|   `-- styles.css
|-- utils/
|   |-- file_loader.py
|   |-- github_loader.py
|   |-- report_analytics.py
|   `-- reporter.py
|-- tests/
|   |-- test_file_loader.py
|   |-- test_engine_text.py
|   |-- test_github_loader.py
|   |-- test_report_analytics.py
|   |-- test_secrets.py
|   |-- test_risks.py
|   |-- test_prompt_leak.py
|   `-- test_web_app.py
|-- requirements.txt
|-- README.md
`-- .gitignore
```

## Risk Scoring

Each finding adds points to a file score:

- Hardcoded secret: 5 points
- Risky function: 3 points
- Prompt leak indicator: 2 points

Risk levels:

- Low: 0-4 points
- Medium: 5-9 points
- High: 10+ points

## Running Tests

```bash
pytest
```

## Limitations

This is an educational, regex-based scanner. It does not replace mature tools such as secret scanners, SAST tools, dependency scanners, or manual security review.

GitHub repository scanning supports public repositories only. It downloads temporary ZIP archives, scans supported files, and deletes the temporary source afterward. The scanner does not modify files, auto-fix issues, install Git hooks, or parse Python with the AST. The web interface is designed for local use and does not include user accounts, persistent scan history, or production deployment settings.

## Future Improvements

- Add optional configuration for ignored files and rules.
- Add private GitHub repository support with `GITHUB_TOKEN`.
- Add entropy-based secret detection.
- Add Git pre-commit hook support.
- Export SARIF for GitHub code scanning.
- Use Python AST parsing for more accurate risky function detection.
