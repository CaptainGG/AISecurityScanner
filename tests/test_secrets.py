from scanner.secrets import detect_secrets


def test_detects_openai_key() -> None:
    findings = detect_secrets(["OPENAI_API_KEY='sk-proj-abcdefghijklmnopqrstuvwxyz123456'"])
    assert findings[0]["issue_type"] == "OpenAI API key"
    assert findings[0]["severity"] == "High"


def test_detects_aws_access_key() -> None:
    findings = detect_secrets(["aws_key = 'AKIAABCDEFGHIJKLMNOP'"])
    assert findings[0]["issue_type"] == "AWS access key"


def test_detects_bearer_token() -> None:
    findings = detect_secrets(["Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456"])
    assert findings[0]["issue_type"] == "Bearer token"


def test_detects_credential_assignment() -> None:
    findings = detect_secrets(['password = "super-secret-value"'])
    assert findings[0]["issue_type"] == "Credential assignment"


def test_detects_email_address() -> None:
    findings = detect_secrets(["Contact admin@example.com for access."])
    assert findings[0]["issue_type"] == "Email address"
    assert findings[0]["severity"] == "Low"
