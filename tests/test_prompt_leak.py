from scanner.prompt_leak import detect_prompt_leaks


def test_detects_prompt_leak_in_python_comment() -> None:
    findings = detect_prompt_leaks(["# system prompt: do not share"], ".py", "app.py")
    assert findings[0]["category"] == "prompt_leak"


def test_detects_prompt_leak_in_markdown_text() -> None:
    findings = detect_prompt_leaks(["The user asked for the internal prompt."], ".md", "notes.md")
    assert len(findings) == 1


def test_detects_prompt_leak_in_env_comment() -> None:
    findings = detect_prompt_leaks(["# token copied from internal prompt"], ".env", ".env")
    assert len(findings) == 1


def test_ignores_harmless_python_variable_usage() -> None:
    findings = detect_prompt_leaks(["token_count = len(tokens)"], ".py", "app.py")
    assert findings == []
