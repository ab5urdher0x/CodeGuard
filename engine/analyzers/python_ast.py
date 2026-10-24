"""Python static analyzer: AST + lightweight taint tracking.

Approach: resolve import aliases, fold constant strings (so 'sub'+'process' and
f-strings over constants are seen), then track which variables carry data from a
dangerous *source* (decoded bytes, remote content, secrets, file data, user input)
into a dangerous *sink* (code execution, shell, network, SQL, file write/delete).
A constant reaching a sink is usually safe; a tainted value is not. Safe idioms
(ast.literal_eval, parameterised SQL, allowlist checks) lower the score.

Never executes the code it analyzes.
"""
import ast

from engine import knowledge as K
from engine.analyzers import shell
from engine.facts import (
    AI_TARGETED_INSTRUCTIONS, CODE_INJECTION, DATA_EXFILTRATION, DEPENDENCY_RISK,
    DESTRUCTIVE_COMMAND, INSECURE_DESERIALIZATION, OBFUSCATED_EXECUTION,
    PERSISTENCE_OR_PRIVESC, RESOURCE_EXHAUSTION, SECRET_ACCESS, SSRF_NETWORK_EXFIL,
    Analysis, Finding,
)

# ---- taint kinds
DECODED, REMOTE, SECRET, FILEDATA, INPUT = "decoded", "remote", "secret", "file", "input"

DECODE_FUNCS = {
    "base64.b64decode", "base64.b85decode", "base64.b32decode", "base64.a85decode", "base64.b16decode",
    "base64.standard_b64decode", "base64.urlsafe_b64decode", "codecs.decode", "bytes.fromhex",
    "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress", "binascii.unhexlify",
    "binascii.a2b_base64", "binascii.a2b_hex",
}
EXEC_FUNCS = {"eval", "exec", "execfile"}
COMPILE_FUNCS = {"compile", "builtins.compile"}
DYNIMPORT_FUNCS = {"__import__", "builtins.__import__", "importlib.import_module", "importlib.__import__",
                   "imp.load_source", "importlib.util.module_from_spec"}
DESERIALIZE_FUNCS = {"pickle.load", "pickle.loads", "cpickle.load", "cpickle.loads", "_pickle.loads",
                     "dill.load", "dill.loads", "shelve.open", "marshal.load", "marshal.loads",
                     "jsonpickle.decode", "yaml.load", "yaml.unsafe_load", "yaml.full_load"}
SHELL_FUNCS = {"os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4", "commands.getoutput",
               "commands.getstatusoutput", "subprocess.call", "subprocess.run", "subprocess.Popen",
               "subprocess.check_call", "subprocess.check_output", "subprocess.getoutput",
               "subprocess.getstatusoutput", "pty.spawn"}
EXEC_OS_FUNCS = {"os.execl", "os.execle", "os.execlp", "os.execv", "os.execve", "os.execvp", "os.execvpe",
                 "os.spawnl", "os.spawnv", "os.posix_spawn"}
NETWORK_SEND = {"requests.post", "requests.put", "requests.patch", "requests.get", "requests.request",
                "requests.delete", "requests.head", "httpx.post", "httpx.get", "httpx.put", "httpx.request",
                "urllib.request.urlopen", "urllib.request.Request", "urllib2.urlopen", "aiohttp.request",
                "http.client.HTTPConnection", "http.client.HTTPSConnection", "smtplib.SMTP",
                "ftplib.FTP", "socket.create_connection", "telnetlib.Telnet"}
NETWORK_READ = {"requests.get", "requests.post", "requests.request", "urllib.request.urlopen",
                "urllib2.urlopen", "httpx.get", "httpx.post"}
ENV_READ = {"os.getenv", "os.environ.get"}
DELETE_FUNCS = {"os.remove", "os.unlink", "os.rmdir", "shutil.rmtree", "pathlib.Path.unlink"}
INPUT_FUNCS = {"input", "raw_input", "sys.argv", "os.environ"}


def _dotted_raw(node) -> str | None:
    """Dotted path of an expression used as a callable, e.g. os.path.join -> 'os.path.join'."""
    parts = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    elif isinstance(cur, ast.Call):
        inner = _dotted_raw(cur.func)
        parts.append("()" + (inner or ""))
    else:
        return None
    return ".".join(reversed(parts))


class PyAnalyzer(ast.NodeVisitor):
    def __init__(self, code: str):
        self.code = code
        self.lines = code.splitlines()
        self.findings: list[Finding] = []
        self.signals: dict[str, float] = {}
        self.aliases: dict[str, str] = {}      # local name -> canonical module/attr
        self.str_consts: dict[str, str] = {}   # module-level constant strings
        self.fmt_vars: dict[str, tuple] = {}   # var -> (text_with_\x00_holes, dynamic)
        self.int_consts: dict[str, int] = {}   # module-level int constants
        self.frag_vars: dict[str, str] = {}    # var -> concatenated constant path/url fragments
        self.node_vars: dict[str, object] = {}  # var -> RHS AST node (last simple assignment)
        self.tainted: dict[str, set] = {}      # var name -> taint kinds
        self.taint_returning: dict[str, set] = {}
        self.param_names: set = set()

    # ---------- setup passes
    def collect(self, tree):
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom) and node.module:
                for a in node.names:
                    self.aliases[a.asname or a.name] = f"{node.module}.{a.name}"
            elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                s = self._const_str(node.value)
                if s is not None and "\x00" not in s:  # only truly-constant strings (no dynamic holes)
                    self.str_consts[node.targets[0].id] = s
                elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, int):
                    self.int_consts[node.targets[0].id] = node.value.value

    def resolve(self, func) -> str:
        raw = _dotted_raw(func) or ""
        head, _, rest = raw.partition(".")
        if head in self.aliases:
            base = self.aliases[head]
            return f"{base}.{rest}" if rest else base
        return raw

    # ---------- constant folding
    def _const_str(self, node) -> str | None:
        if isinstance(node, ast.Constant):
            return node.value if isinstance(node.value, str) else None
        if isinstance(node, ast.Name):
            return self.str_consts.get(node.id)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            l, r = self._const_str(node.left), self._const_str(node.right)
            return (l + r) if l is not None and r is not None else None
        if isinstance(node, ast.JoinedStr):
            out = []
            for v in node.values:
                if isinstance(v, ast.Constant):
                    out.append(str(v.value))
                elif isinstance(v, ast.FormattedValue):
                    s = self._const_str(v.value)
                    out.append(s if s is not None else "\x00")  # mark dynamic hole
                else:
                    return None
            return "".join(out)
        if isinstance(node, ast.Call):
            fn = self.resolve(node.func)
            if fn in ("os.path.join", "posixpath.join", "ntpath.join"):
                parts = [self._const_str(a) for a in node.args]
                return "/".join(p for p in parts if p) if all(p is not None for p in parts) else None
            if fn in ("os.path.expanduser",) and node.args:
                s = self._const_str(node.args[0])
                return s.replace("~", "/home/user") if s else None
            if isinstance(node.func, ast.Attribute) and node.func.attr == "join":
                sep = self._const_str(node.func.value)
                return None if sep is None else sep  # best-effort
        return None

    def _joined_has_dynamic(self, node) -> bool:
        return isinstance(node, ast.JoinedStr) and any(isinstance(v, ast.FormattedValue) for v in node.values)

    def _str_follow(self, node) -> tuple:
        """Resolve a node to (string_template_with_\x00_holes, is_dynamic), following variables
        and % / .format / f-string formatting. Returns (None, False) if not string-like."""
        if node is None:
            return None, False
        if isinstance(node, ast.Name):
            if node.id in self.str_consts:
                return self.str_consts[node.id], False
            if node.id in self.fmt_vars:
                return self.fmt_vars[node.id]
            return None, False
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            left, _ = self._str_follow(node.left)
            if left is None:
                left = self._const_str(node.left)
            if left is not None:
                return left, True
            return None, False
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
            base = self._const_str(node.func.value)
            if base is None:
                base, _ = self._str_follow(node.func.value)
            if base is not None:
                return base, True
            return None, False
        s = self._const_str(node)
        if s is not None:
            return s, ("\x00" in s)
        return None, False

    # ---------- taint
    def _taint_of(self, node) -> set:
        if node is None:
            return set()
        if isinstance(node, ast.Name):
            if node.id in self.tainted:
                return self.tainted[node.id]
            return {INPUT} if node.id in self.param_names else set()
        if isinstance(node, ast.Call):
            return self._taint_of_call(node)
        if isinstance(node, (ast.BinOp,)):
            return self._taint_of(node.left) | self._taint_of(node.right)
        if isinstance(node, ast.JoinedStr):
            t = set()
            for v in node.values:
                if isinstance(v, ast.FormattedValue):
                    t |= self._taint_of(v.value)
            return t
        if isinstance(node, (ast.Attribute, ast.Subscript, ast.Starred)):
            return self._taint_of(node.value)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            t = set()
            for e in node.elts:
                t |= self._taint_of(e)
            return t
        if isinstance(node, ast.Dict):
            t = set()
            for v in node.values:
                t |= self._taint_of(v)
            return t
        return set()

    def _taint_of_call(self, node: ast.Call) -> set:
        fn = self.resolve(node.func)
        # chained: requests.get(...).text / .read()  — fn looks like '().requests.get' style; detect via attribute value call
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
            inner = self.resolve(node.func.value.func)
            if inner in NETWORK_READ:
                return {REMOTE}
        if fn in DECODE_FUNCS:
            return {DECODED} | self._taint_of(node.args[0]) if node.args else {DECODED}
        if fn in NETWORK_READ:
            return {REMOTE}
        if fn in ENV_READ:
            name = self._const_str(node.args[0]) if node.args else None
            return {SECRET} if name and K.is_secret_env_name(name) else {INPUT}
        if fn in ("os.environ.items", "os.environ.values", "os.environ.copy", "os.environ.keys",
                  "os.environ.as_dict") or (fn == "dict" and node.args
                                            and _dotted_raw(node.args[0]) in ("os.environ", "environ")):
            self.sig("taint.env_bulk_read")  # bulk read of all env vars (likely to include secrets)
            return {SECRET}
        if fn in ("input", "raw_input"):
            return {INPUT}
        if fn == "open" and node.args:
            path = self._const_str(node.args[0])
            if path and K.is_secret_path(path):
                return {SECRET}
            if path and K.is_sensitive_data_path(path):
                return {FILEDATA}
            return {FILEDATA} if path is None else set()
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("read", "readlines", "text", "json", "content"):
            return self._taint_of(node.func.value)
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "pop", "setdefault"):
            t = self._taint_of(node.func.value)
            for a in node.args:
                t |= self._taint_of(a)
            return t
        # user function that returns taint
        if fn in self.taint_returning:
            return self.taint_returning[fn]
        base = fn.split(".")[0]
        if base in self.taint_returning:
            return self.taint_returning[base]
        # propagate args for unknown wrappers (helps one-level wrappers)
        t = set()
        for a in node.args:
            t |= self._taint_of(a)
        return t

    def _line(self, node):
        return getattr(node, "lineno", None)

    def add(self, cat, score, node, rule, msg, sub=None, intel=None):
        self.findings.append(Finding(cat, score, self._line(node), rule, msg, sub, intel))

    def sig(self, name, val=1.0):
        self.signals[name] = max(self.signals.get(name, 0.0), val)

    # ---------- statement visitors
    def visit_FunctionDef(self, node):
        saved = self.param_names
        self.param_names = saved | {a.arg for a in node.args.args + node.args.kwonlyargs}
        if node.args.vararg:
            self.param_names.add(node.args.vararg.arg)
        self.generic_visit(node)
        self.param_names = saved

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Assign(self, node):
        self.generic_visit(node)
        t = self._taint_of(node.value)
        names = [n for tgt in node.targets for n in _target_names(tgt)]
        if t:
            for name in names:
                self.tainted[name] = self.tainted.get(name, set()) | t
        txt, dyn = self._str_follow(node.value)
        if txt is not None and dyn:
            for name in names:
                self.fmt_vars[name] = (txt, True)
        frag = _const_fragments(node.value)
        if frag and (self._const_str(node.value) is None):  # dynamic path/url with constant parts
            for name in names:
                self.frag_vars[name] = frag
        if isinstance(node.value, ast.Call):  # remember RHS expression for structural checks
            for name in names:
                self.node_vars[name] = node.value

    def visit_AnnAssign(self, node):
        self.generic_visit(node)
        if node.value and isinstance(node.target, ast.Name):
            t = self._taint_of(node.value)
            if t:
                self.tainted[node.target.id] = t

    def visit_Call(self, node):
        self.generic_visit(node)
        fn = self.resolve(node.func)
        arg0 = node.args[0] if node.args else None

        # ---- code execution
        if fn in EXEC_FUNCS or fn in ("builtins.eval", "builtins.exec"):
            t = self._taint_of(arg0)
            const = self._const_str(arg0)
            if DECODED in t or REMOTE in t:
                self.add(OBFUSCATED_EXECUTION, 0.95, node, "py.exec.decoded",
                         f"{fn}() runs decoded/remote data (obfuscated payload execution)")
                self.sig("taint.decoded_to_exec" if DECODED in t else "taint.remote_to_exec")
            elif const is None:  # dynamic expression, not a literal
                sev = 0.88 if (INPUT in t or SECRET in t) else 0.8
                self.add(OBFUSCATED_EXECUTION, sev, node, "py.exec.dynamic",
                         f"{fn}() executes a runtime-built expression/string")
                if INPUT in t:
                    self.sig("taint.input_to_exec")
            else:
                self.add(OBFUSCATED_EXECUTION, 0.6, node, "py.exec.const", f"{fn}() of a string literal")
            self.sig("sink.exec_const")
        elif fn in COMPILE_FUNCS and arg0 is not None and self._const_str(arg0) is None:
            self.add(OBFUSCATED_EXECUTION, 0.7, node, "py.compile.dynamic", "compile() of a runtime-built string")
        elif fn in DYNIMPORT_FUNCS:
            name = self._const_str(arg0) if arg0 is not None else None
            dynamic = arg0 is not None and name is None
            folded = name and "\x00" not in name
            if folded and name in ("subprocess", "os") or dynamic:
                self.add(OBFUSCATED_EXECUTION, 0.82, node, "py.import.dynamic",
                         f"dynamic import via {fn}() hides the imported module name")
            elif folded:
                self.add(OBFUSCATED_EXECUTION, 0.5, node, "py.import.dynamic", f"dynamic import of '{name}'")
            self.sig("sink.dynamic_import")

        # ---- deserialization
        elif fn in DESERIALIZE_FUNCS:
            safe_yaml = fn == "yaml.load" and any(
                (kw.arg == "Loader" and "Safe" in (_dotted_raw(kw.value) or "")) for kw in node.keywords)
            if not safe_yaml:
                sev = 0.85 if fn in ("pickle.load", "pickle.loads", "shelve.open", "dill.loads", "yaml.load",
                                     "marshal.loads") else 0.7
                self.add(OBFUSCATED_EXECUTION, sev, node, "py.deserialize",
                         f"{fn}() on untrusted data can execute arbitrary code", sub=INSECURE_DESERIALIZATION)
                self.sig("sink.deserialize")

        # ---- shell execution
        elif fn in SHELL_FUNCS:
            self._check_shell(node, fn)
        elif fn in EXEC_OS_FUNCS:
            self.add(OBFUSCATED_EXECUTION, 0.55, node, "py.os.exec", f"{fn}() replaces the process image")

        # ---- network
        elif fn in NETWORK_SEND:
            self._check_network(node, fn)

        # ---- sql
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany", "executescript"):
            self._check_sql(node)

        # ---- file open (write) / delete
        elif fn == "open":
            self._check_open(node)
        elif fn in DELETE_FUNCS or (isinstance(node.func, ast.Attribute) and node.func.attr == "unlink"):
            self._check_delete(node, fn)
        elif fn in ("os.chmod", "os.chown", "os.setuid", "os.setgid"):
            mode = node.args[1] if len(node.args) > 1 else None
            if fn == "os.chmod" and isinstance(mode, ast.Constant) and isinstance(mode.value, int) and mode.value & 0o4000:
                self.add(PERSISTENCE_OR_PRIVESC, 0.85, node, "py.chmod.setuid", "sets the setuid bit via os.chmod")
            elif fn in ("os.setuid", "os.setgid") and isinstance(arg0, ast.Constant) and arg0.value == 0:
                self.add(PERSISTENCE_OR_PRIVESC, 0.6, node, "py.setuid.root", "drops to uid 0 (root)")

        # ---- dependency install via subprocess handled in _check_shell; pip main
        elif fn in ("pip.main", "pip._internal.main"):
            self._check_pip_list(node.args, node)

        # ---- decode of a constant blob that is itself a shell/destructive command
        elif fn in DECODE_FUNCS and arg0 is not None:
            self._check_decoded_payload(node, arg0)

        # ---- raw socket to a reverse-shell port
        elif fn in ("socket.create_connection",) or (isinstance(node.func, ast.Attribute)
                                                     and node.func.attr == "connect"):
            self._check_socket(node)

        # ---- resource: huge allocation
        self._check_alloc(node, fn)

    def visit_While(self, node):
        self.generic_visit(node)
        if isinstance(node.test, ast.Constant) and node.test.value:
            body = ast.walk(node)
            has_exit = any(isinstance(n, (ast.Break, ast.Return)) for n in ast.walk(node))
            has_block = any(
                self.resolve(n.func) in ("time.sleep", "queue.Queue.get", "socket.accept") or
                (isinstance(n.func, ast.Attribute) and n.func.attr in ("sleep", "join", "wait", "recv", "accept", "get"))
                for n in ast.walk(node) if isinstance(n, ast.Call))
            if not has_exit and not has_block:
                self.add(RESOURCE_EXHAUSTION, 0.78, node, "py.loop.infinite",
                         "while True with no break/return or blocking call (busy loop)")
                self.sig("loop.unbounded")

    _SPAWN_CALLS = ("threading.Thread", "multiprocessing.Process", "os.fork", "subprocess.Popen",
                    "socket.socket", "asyncio.create_task", "socket.create_connection")

    def _loop_spawn(self, node, iter_node):
        n = _range_size(iter_node, self)
        if n is None or n < 100:  # only flag a known, large fan-out (bounded pools are benign)
            return
        spawns = [c for c in ast.walk(node) if isinstance(c, ast.Call) and self.resolve(c.func) in self._SPAWN_CALLS]
        if spawns:
            self.add(RESOURCE_EXHAUSTION, 0.8 if n >= 1000 else 0.7, node, "py.loop.spawn",
                     f"spawns threads/processes/sockets {n} times in a loop (resource exhaustion)")
            self.sig("loop.spawn")

    def visit_For(self, node):
        self.generic_visit(node)
        self._loop_spawn(node, node.iter)

    def _visit_comp(self, node):
        self.generic_visit(node)
        for gen in node.generators:
            self._loop_spawn(node, gen.iter)

    visit_ListComp = _visit_comp
    visit_SetComp = _visit_comp
    visit_GeneratorExp = _visit_comp
    visit_DictComp = _visit_comp

    def _check_shell(self, node, fn):
        shell_kw = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in node.keywords)
        implicit_shell = fn in ("os.system", "os.popen", "os.popen2", "os.popen3", "os.popen4",
                                "commands.getoutput", "commands.getstatusoutput", "subprocess.getoutput")
        arg0 = node.args[0] if node.args else None
        tainted = bool(self._taint_of(arg0) & {INPUT, DECODED, REMOTE})
        self.sig("sink.shell_string")
        list_form = isinstance(arg0, (ast.List, ast.Tuple))
        if list_form:
            toks = [self._const_str(e) or "\x00" for e in arg0.elts]
            self._check_argv(toks, node)
            text = " ".join(t if t != "\x00" else "{VAR}" for t in toks)
            cmd, dynamic = text, "\x00" in "".join(toks)
        else:
            text_full, dynamic = self._str_follow(arg0)
            cmd = text_full
            dynamic = dynamic or (cmd is not None and "\x00" in cmd)
            if cmd is None and arg0 is not None:
                dynamic = True
        text = (cmd or "").replace("\x00", "{VAR}")
        if text.strip():
            for f in shell.analyze_command(text, self._line(node), origin="py",
                                           dynamic=(dynamic or tainted) and not list_form):
                self.findings.append(f)
        is_shell = shell_kw or implicit_shell
        if is_shell and (dynamic or tainted) and not list_form:
            sev = 0.85 if tainted else (0.68 if cmd is not None else 0.62)
            self.add(DESTRUCTIVE_COMMAND, sev, node, "py.shell.injection",
                     "user/dynamic data flows into a shell command (command injection)", sub=CODE_INJECTION)
            if INPUT in self._taint_of(arg0):
                self.sig("taint.input_to_shell")
        elif list_form and tainted:
            self.add(DESTRUCTIVE_COMMAND, 0.55, node, "py.shell.taint_arg",
                     "user/dynamic data passed as a subprocess argument")

    def _check_argv(self, toks, node):
        if not toks:
            return
        low = [t.lower() for t in toks]
        for i, t in enumerate(low):
            if t.endswith(("pip", "pip3")) and i + 1 < len(low) and low[i + 1] == "install":
                self.findings.extend(shell.analyze_install(toks[i:], self._line(node), origin="py"))
                self.sig("dep.install")
            if t in ("npm", "yarn", "pnpm") and i + 1 < len(low) and low[i + 1] in ("install", "add", "i"):
                self.findings.extend(shell.analyze_install(toks[i:], self._line(node), origin="py"))
                self.sig("dep.install")

    def _check_pip_list(self, args, node):
        if args and isinstance(args[0], (ast.List, ast.Tuple)):
            toks = [self._const_str(e) or "" for e in args[0].elts]
            if "install" in toks:
                self.findings.extend(shell.analyze_install(["pip"] + toks, self._line(node), origin="py"))

    def _check_network(self, node, fn):
        self.sig("sink.network")
        url_node = node.args[0] if node.args else None
        url = self._const_str(url_node)
        for kw in node.keywords:
            if kw.arg == "url" and url is None:
                url = self._const_str(kw.value)
                url_node = kw.value if url is None else url_node
        # concatenated URL ('http://host/' + path): classify the constant prefix (the host)
        if url is None and url_node is not None:
            frag = _const_fragments(url_node) or (self.frag_vars.get(url_node.id) if isinstance(url_node, ast.Name) else None)
            if frag and "://" in frag:
                url = frag
        if url:
            risk, host = K.classify_url(url.replace("\x00", ""))
            if risk == "metadata":
                self.add(SSRF_NETWORK_EXFIL, 0.9, node, "py.ssrf.metadata",
                         f"request to cloud metadata endpoint {host} (credential theft)",
                         intel="black_october:imds" if "169.254" in url else None)
                self.sig("net.metadata_host")
            elif risk == "internal":
                self.add(SSRF_NETWORK_EXFIL, 0.72, node, "py.ssrf.internal", f"request to internal/private host {host}")
                self.sig("net.internal_host")
            elif risk == "loopback":  # localhost is common in benign dev; weak signal, won't block alone
                self.add(SSRF_NETWORK_EXFIL, 0.35, node, "py.ssrf.loopback", f"request to loopback host {host}")
                self.sig("net.internal_host")
            elif risk == "risky_scheme":
                self.add(SSRF_NETWORK_EXFIL, 0.8, node, "py.ssrf.scheme", f"request using a dangerous URL scheme ({url[:40]})")
            elif risk == "lookalike":
                self.add(DATA_EXFILTRATION, 0.82, node, "py.exfil.lookalike",
                         f"request to lookalike domain {host} (imitates a trusted brand)", intel="black_october:lookalike")
                self.sig("net.lookalike_domain")
            elif risk == "exfil_dest":
                self.add(DATA_EXFILTRATION, 0.78, node, "py.exfil.dest", f"request to suspicious destination {host}")
                self.sig("net.exfil_dest")
        # payload taint -> exfiltration
        payload_taint = set()
        for a in node.args[1:]:
            payload_taint |= self._taint_of(a)
        for kw in node.keywords:
            if kw.arg in ("data", "json", "files", "params", "body", "content"):
                payload_taint |= self._taint_of(kw.value)
        if SECRET in payload_taint:
            self.add(DATA_EXFILTRATION, 0.82, node, "py.exfil.secret", "sends secret/credential data to a remote endpoint")
            self.sig("taint.secret_to_network")
        elif FILEDATA in payload_taint:
            self.add(DATA_EXFILTRATION, 0.7, node, "py.exfil.file", "sends local file data to a remote endpoint")
            self.sig("taint.file_to_network")
        elif _payload_cred_fields(node):
            # credential-named fields (password/token/secret/...) posted to a remote host.
            # Legit login flows look identical statically, so this is a moderate signal.
            self.add(DATA_EXFILTRATION, 0.6, node, "py.exfil.credfield",
                     "sends credential-named fields (e.g. password/token) to a network endpoint")
            self.sig("taint.secret_to_network")

    def _check_sql(self, node):
        arg0 = node.args[0] if node.args else None
        has_params = len(node.args) > 1 or any(kw.arg in ("params", "parameters", "vars") for kw in node.keywords)
        sql, dynamic = self._str_follow(arg0)
        text = (sql or "").replace("\x00", " ")
        verb = text.strip().split()[0].upper() if text.strip() else ""
        if dynamic and verb:
            self.sig("sql.formatted")
            if verb in ("DELETE", "DROP", "TRUNCATE", "UPDATE", "ALTER"):
                self.add(DESTRUCTIVE_COMMAND, 0.8, node, "py.sql.injection_destructive",
                         f"formatted/f-string SQL with a {verb} (injection can destroy data)", sub=CODE_INJECTION)
                self.sig("taint.input_to_sql")
            elif verb in ("SELECT", "INSERT", "WITH"):
                self.add(DATA_EXFILTRATION, 0.72, node, "py.sql.injection_select",
                         f"formatted/f-string SQL with a {verb} (injection can dump data)", sub=CODE_INJECTION)
                self.sig("taint.input_to_sql")
        elif has_params and not dynamic:
            self.sig("safe.parameterized_sql")

    def _check_open(self, node):
        path = self._const_str(node.args[0]) if node.args else None
        if path is None and node.args:  # dynamic path: inspect its constant fragments
            arg = node.args[0]
            path = _const_fragments(arg) or (self.frag_vars.get(arg.id) if isinstance(arg, ast.Name) else None)
        mode = self._const_str(node.args[1]) if len(node.args) > 1 else None
        for kw in node.keywords:
            if kw.arg == "mode":
                mode = self._const_str(kw.value)
        writing = mode and any(m in mode for m in ("w", "a", "x", "+"))
        if path and writing:
            if K.is_startup_hook(path):
                self.add(PERSISTENCE_OR_PRIVESC, 0.9, node, "py.persist.startup_hook",
                         f"writes a Python startup hook ({path}) — runs on every interpreter start",
                         intel="black_october:startup-hook")
                self.sig("persist.startup_hook")
            elif (pt := K.persistence_target(path)):
                self.add(PERSISTENCE_OR_PRIVESC, 0.82, node, "py.persist.write", f"writes to persistence location {pt}")
                self.sig("persist.path_write")
            self.sig("sink.file_write")
        elif path and not writing and K.is_secret_path(path):
            self.add(SECRET_ACCESS, 0.78, node, "py.secret.read", f"reads credential file {path}")
            self.sig("taint.secret_read")

    def _check_delete(self, node, fn):
        arg0 = node.args[0] if node.args else None
        path = self._const_str(arg0)
        tainted = bool(self._taint_of(arg0) & {INPUT, REMOTE})
        self.sig("sink.file_delete")
        if path and "\x00" not in path and K.is_dangerous_delete_target(path):
            self.add(DESTRUCTIVE_COMMAND, 0.9, node, "py.delete.critical", f"deletes critical path {path}")
        elif fn == "shutil.rmtree" and (tainted or path is None or "\x00" in (path or "")):
            # A deletion confined to a constant prefix whose dynamic part is basename()-
            # sanitized cannot escape its subtree -> low risk. Note: a constant prefix
            # ALONE is not enough (os.path.join('/tmp', name) escapes via '../'); the
            # basename() guard is what makes it safe.
            resolved = self.node_vars.get(arg0.id) if isinstance(arg0, ast.Name) else arg0
            if _is_confined_delete(resolved):
                self.add(DESTRUCTIVE_COMMAND, 0.2, node, "py.delete.confined",
                         "recursive delete confined to a constant prefix (basename-sanitized)")
            else:
                self.add(DESTRUCTIVE_COMMAND, 0.72 if tainted else 0.55, node, "py.delete.tree",
                         "recursive delete of a runtime-controlled path")
                if tainted:
                    self.sig("taint.input_to_path_delete")

    def _check_decoded_payload(self, node, arg0):
        """b64decode('...') of a CONSTANT whose decoded bytes look like a shell/destructive
        command — an obfuscation indicator even if the result is only printed, not executed."""
        blob = self._const_str(arg0)
        if not blob or "\x00" in blob:
            return
        import base64 as _b64
        try:
            decoded = _b64.b64decode(blob, validate=False).decode("utf-8", "ignore")
        except Exception:
            return
        if _looks_like_command(decoded):
            self.add(OBFUSCATED_EXECUTION, 0.6, node, "py.decode.command_blob",
                     f"base64 blob decodes to a shell/destructive command: {decoded[:40]!r}")
            self.sig("sink.exec_const")

    def _check_socket(self, node):
        """socket.connect((host, port)) / create_connection to a reverse-shell port, or an
        external host while subprocess/pty is imported (reverse-shell indicators)."""
        addr = node.args[0] if node.args else None
        port = host = None
        if isinstance(addr, (ast.Tuple, ast.List)) and len(addr.elts) >= 2:
            host = self._const_str(addr.elts[0]) or _const_fragments(addr.elts[0])
            p = addr.elts[1]
            if isinstance(p, ast.Constant) and isinstance(p.value, int):
                port = p.value
        susp_port = port in (4444, 1337, 31337, 9001, 5555, 6666, 1234)
        has_shell_mod = bool({"subprocess", "pty"} & set(self.aliases.values()))
        if susp_port:
            self.add(DATA_EXFILTRATION, 0.65, node, "py.socket.revshell_port",
                     f"outbound socket to a common reverse-shell port ({port})")
            self.sig("sink.network")
        elif host and K.classify_host(host) is None and has_shell_mod:
            self.add(DATA_EXFILTRATION, 0.5, node, "py.socket.external_withshell",
                     "outbound socket to an external host alongside subprocess/pty (reverse-shell indicator)")

    def _check_alloc(self, node, fn):
        if fn in ("bytearray", "bytes") and node.args and isinstance(node.args[0], ast.Constant) \
                and isinstance(node.args[0].value, int) and node.args[0].value >= 10**9:
            self.add(RESOURCE_EXHAUSTION, 0.6, node, "py.alloc.huge", "allocates a very large buffer")
            self.sig("alloc.huge")
        if fn == "os.fork":
            self.add(RESOURCE_EXHAUSTION, 0.5, node, "py.fork", "os.fork() (fork-bomb risk if unbounded)")


def _is_confined_delete(node) -> bool:
    """True when a path is os.path.join(<constant_prefix>, ...) and every non-constant
    component is wrapped in os.path.basename()/os.path.split() (cannot traverse up).
    A constant prefix without bas: NOT confined (../ can escape)."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "join"):
        return False
    args = node.args
    if not args or not isinstance(args[0], ast.Constant) or not isinstance(args[0].value, str):
        return False  # first segment must be a constant prefix
    if args[0].value.startswith(("/", "~")) is False and ".." in args[0].value:
        return False
    for a in args[1:]:
        if isinstance(a, ast.Constant):
            if isinstance(a.value, str) and ".." in a.value:
                return False
            continue
        if isinstance(a, ast.Call) and isinstance(a.func, ast.Attribute) and a.func.attr in ("basename", "split"):
            continue
        return False  # a raw dynamic component can contain '../' -> not confined
    return True


def _const_fragments(node) -> str:
    """Concatenate all constant string literals under an expression (dynamic paths/URLs)."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return "".join(out)


import re as _re  # noqa: E402

_CRED_FIELD_RX = _re.compile(
    r"(pass(word|wd|phrase)?|secret|token|api[_-]?key|private[_-]?key|credential|access[_-]?key|"
    r"auth[_-]?token|refresh[_-]?token|cvv|card[_-]?number)", _re.I)


_CMD_RX = _re.compile(
    r"\b(rm\s+-rf|rm\s+-r|dd\s+if=|mkfs|chmod\s+[0-7]|chown\s|curl\s|wget\s|nc\s|/bin/(sh|bash)|"
    r"base64\s+-d|eval\s|exec\s|:\(\)\s*\{|sudo\s|crontab|iptables|systemctl|kill\s+-9|shutdown|reboot)\b")


def _looks_like_command(text) -> bool:
    return bool(_CMD_RX.search(text or ""))


def _payload_cred_fields(call_node) -> bool:
    """True if a network call's payload (json=/data=/body= or 2nd positional) is a dict with
    credential-named keys (password, token, secret, ...). 'username' alone does not count."""
    payloads = [kw.value for kw in call_node.keywords if kw.arg in ("json", "data", "body", "content")]
    payloads += call_node.args[1:2]
    for p in payloads:
        if isinstance(p, ast.Dict):
            for k in p.keys:
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and _CRED_FIELD_RX.search(k.value):
                    return True
    return False


def _target_names(tgt):
    if isinstance(tgt, ast.Name):
        return [tgt.id]
    if isinstance(tgt, (ast.Tuple, ast.List)):
        out = []
        for e in tgt.elts:
            out.extend(_target_names(e))
        return out
    return []


def _range_size(iter_node, az):
    if isinstance(iter_node, ast.Call) and az.resolve(iter_node.func) in ("range", "builtins.range"):
        last = iter_node.args[-1] if iter_node.args else None
        if isinstance(last, ast.Constant) and isinstance(last.value, int):
            return last.value
        if isinstance(last, ast.Name) and last.id in az.int_consts:
            return az.int_consts[last.id]
    return None


def _prepass_returns(tree, az):
    """One pass: mark user functions that return a tainted value (params treated as INPUT)."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            az.param_names = {a.arg for a in node.args.args}
            for sub in ast.walk(node):
                if isinstance(sub, ast.Return) and sub.value is not None:
                    t = az._taint_of(sub.value)
                    if t:
                        az.taint_returning[node.name] = az.taint_returning.get(node.name, set()) | t
    az.param_names = set()


def analyze(code: str, analysis: Analysis) -> None:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        analysis.parse_ok = False
        return
    az = PyAnalyzer(code)
    az.collect(tree)
    _prepass_returns(tree, az)
    az.visit(tree)
    analysis.findings.extend(az.findings)
    for k, v in az.signals.items():
        analysis.signals[k] = max(analysis.signals.get(k, 0.0), v)
