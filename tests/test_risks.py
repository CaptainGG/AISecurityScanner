from scanner.risks import detect_risky_code


def test_detects_eval_in_python() -> None:
    findings = detect_risky_code(["result = eval(user_input)"], ".py")
    assert findings[0]["issue_type"] == "eval()"


def test_detects_pickle_load() -> None:
    findings = detect_risky_code(["data = pickle.load(handle)"], ".py")
    assert findings[0]["issue_type"] == "pickle.load()"


def test_detects_subprocess_run_shell_true() -> None:
    findings = detect_risky_code(['subprocess.run("ls", shell=True)'], ".py")
    assert findings[0]["issue_type"] == "subprocess.run(shell=True)"


def test_ignores_risky_words_in_non_python_files() -> None:
    findings = detect_risky_code(["eval(user_input)"], ".md")
    assert findings == []
