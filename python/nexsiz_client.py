#!/usr/bin/env python3
"""
Nexsiz RPC client – campaign control, oracle, protocol, integrity, encryptor,
mutator hooks, structured seed generation.
Author  : Revana / Nexsiz Toolsmith
Date    : 06/08/2026
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import socket
from typing import Any, Callable, Dict, List, Optional, Sequence, Union


class Campaign:
    def __init__(self, sock_path: str = "/tmp/nexsiz.sock", timeout: float = 5.0):
        self.sock_path = sock_path
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None
        self._id = 0

    def connect(self) -> "Campaign":
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self.sock_path)
        self._sock = s
        return self

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    def __enter__(self) -> "Campaign":
        return self.connect()

    def __exit__(self, *args) -> None:
        self.close()

    def _call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if self._sock is None:
            raise RuntimeError("not connected")
        self._id += 1
        req = {"id": self._id, "method": method, "params": params or {}}
        self._sock.sendall((json.dumps(req, separators=(",", ":")) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("RPC closed")
            buf += chunk
        resp = json.loads(buf.split(b"\n", 1)[0].decode())
        if not resp.get("ok", False):
            raise RuntimeError(resp.get("error", "RPC error"))
        return resp.get("result")

    def ping(self) -> bool:
        return bool(self._call("ping").get("pong"))

    def version(self) -> Dict[str, Any]:
        return self._call("version")

    def stats(self) -> Dict[str, Any]:
        return self._call("stats")

    def stop(self) -> bool:
        return bool(self._call("stop").get("stopped"))

    def load_seeds(self, dir: Optional[str] = None) -> Dict[str, Any]:
        return self._call("load_seeds", {} if dir is None else {"dir": dir})

    def add_seed_raw(self, data: bytes, name: str = "rpc_seed") -> Dict[str, Any]:
        return self._call(
            "add_seed_raw",
            {"data_b64": base64.b64encode(data).decode("ascii"), "name": name},
        )

    def add_seed_structured(self, messages: List[Dict[str, Any]], name: str = "structured") -> Dict[str, Any]:
        return self._call("add_seed_structured", {"name": name, "messages": messages})

    def export_corpus(self, dir: Optional[str] = None) -> Dict[str, Any]:
        return self._call("export_corpus", {} if dir is None else {"dir": dir})

    def get_config(self) -> Dict[str, Any]:
        return self._call("get_config")

    def list_methods(self) -> list:
        return self._call("list_methods")

    def register_protocol(self, params: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("register_protocol", params)

    def register_integrity(self, strategy: str) -> Dict[str, Any]:
        return self._call("register_integrity", {"strategy": strategy})

    def register_encryptor(self, name: str, key: Optional[str] = None) -> Dict[str, Any]:
        p: Dict[str, Any] = {"name": name}
        if key is not None:
            p["key"] = key
        return self._call("register_encryptor", p)

    def register_mutator(
        self, extra_dictionary: Sequence[Any], extend: bool = False
    ) -> Dict[str, Any]:
        return self._call(
            "register_mutator",
            {"extra_dictionary": list(extra_dictionary), "extend": extend},
        )

    def unregister_mutator(self) -> Dict[str, Any]:
        return self._call("unregister_mutator")

    def mutator_status(self) -> Dict[str, Any]:
        return self._call("mutator_status")

    def integrity_status(self) -> Dict[str, Any]:
        return self._call("integrity_status")

    def encryptor_status(self) -> Dict[str, Any]:
        return self._call("encryptor_status")

    def protocol_status(self) -> Dict[str, Any]:
        return self._call("protocol_status")

    def oracle_status(self) -> Dict[str, Any]:
        return self._call("oracle_status")


class Oracle:
    def is_interesting(self, result: Dict[str, Any]) -> bool:
        if result.get("crash") or result.get("hang"):
            return True
        if result.get("outcome") in ("crash", "hang", "connection_reset"):
            return True
        if result.get("coverage_hits", 0) > 0:
            return True
        return False

    def serve_oracle(self, sock_path: str = "/tmp/nexsiz.sock") -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path)
        s.sendall(b'{"id":1,"method":"register_oracle","params":{}}\n')
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(4096)
            if not chunk:
                raise ConnectionError("disconnected")
            buf += chunk
        ack = json.loads(buf.split(b"\n", 1)[0].decode())
        if not ack.get("ok"):
            raise RuntimeError(ack.get("error", "register failed"))
        print("[+] Python oracle registered", flush=True)
        s.settimeout(None)
        leftover = buf.split(b"\n", 1)[1] if b"\n" in buf else b""
        while True:
            while b"\n" not in leftover:
                chunk = s.recv(65536)
                if not chunk:
                    print("[*] Oracle closed", flush=True)
                    return
                leftover += chunk
            line, leftover = leftover.split(b"\n", 1)
            line = line.decode().strip()
            if not line:
                continue
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                continue
            if req.get("method") != "is_interesting":
                continue
            try:
                interesting = bool(self.is_interesting(req.get("params") or {}))
            except Exception:
                interesting = False
            resp = {"id": req.get("id"), "ok": True, "result": {"interesting": interesting}}
            s.sendall((json.dumps(resp, separators=(",", ":")) + "\n").encode())


class SeedBuilder:
    """Structured seed generator – messages with typed/protected fields.

    Does NOT touch the integrity pipeline; seeds enter the corpus only.
    Repair runs later when workers mutate + send (single owner in worker).
    """

    def __init__(self, name: str = "structured"):
        self.name = name
        self._messages: List[Dict[str, Any]] = []

    def message(self, name: str = "msg") -> "_Msg":
        m: Dict[str, Any] = {"name": name, "fields": []}
        self._messages.append(m)
        return _Msg(m)

    def to_params(self) -> Dict[str, Any]:
        return {"name": self.name, "messages": self._messages}

    def register(self, sock_path: str = "/tmp/nexsiz.sock") -> Dict[str, Any]:
        with Campaign(sock_path) as c:
            r = c.add_seed_structured(self._messages, name=self.name)
            print(f"[+] Structured seed: {r}", flush=True)
            return r


class _Msg:
    def __init__(self, m: Dict[str, Any]):
        self._m = m

    def field(
        self,
        name: str,
        data: Union[str, bytes],
        type: str = "binary",
        protected: bool = False,
        encoding: Optional[str] = None,
    ) -> "_Msg":
        f: Dict[str, Any] = {"name": name, "type": type}
        if isinstance(data, bytes):
            f["encoding"] = encoding or "base64"
            f["data"] = base64.b64encode(data).decode("ascii")
        else:
            f["data"] = data
            if encoding:
                f["encoding"] = encoding
        if protected:
            f["protected"] = True
        self._m["fields"].append(f)
        return self


class MutatorHooks:
    """Push extra dictionary tokens into live worker mutators.

    No pre/post reverse-RPC (avoids hot-path latency and double-repair).
    Tokens are merged into the mutator dictionary only.
    """

    def __init__(self, tokens: Optional[Sequence[Any]] = None):
        self.tokens: List[Any] = list(tokens or [])

    def add(self, *tokens: Any) -> "MutatorHooks":
        self.tokens.extend(tokens)
        return self

    def register(self, sock_path: str = "/tmp/nexsiz.sock", extend: bool = False) -> Dict[str, Any]:
        with Campaign(sock_path) as c:
            r = c.register_mutator(self.tokens, extend=extend)
            print(f"[+] Mutator hooks: {r}", flush=True)
            return r


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sock", default=os.environ.get("NEXSIZ_RPC_SOCK", "/tmp/nexsiz.sock"))
    ap.add_argument("--oracle", action="store_true")
    ap.add_argument("--seed-demo", action="store_true", help="Inject structured FTP login seed")
    ap.add_argument("--mutator-demo", action="store_true", help="Push extra mutator dictionary")
    args = ap.parse_args()

    if args.oracle:
        Oracle().serve_oracle(args.sock)
        return

    if args.seed_demo:
        sb = SeedBuilder("ftp_login")
        sb.message("user").field("cmd", "USER", type="command").field(
            "sp", " ", protected=True
        ).field("arg", "anonymous", type="string").field(
            "crlf", "\r\n", protected=True
        )
        sb.message("pass").field("cmd", "PASS", type="command").field(
            "sp", " ", protected=True
        ).field("arg", "guest", type="string").field("crlf", "\r\n", protected=True)
        sb.register(args.sock)
        return

    if args.mutator_demo:
        MutatorHooks(["SITE", "CHMOD", "777", "%n%n%n", b"\x00\xff"]).register(args.sock)
        return

    with Campaign(args.sock) as c:
        print("[+] version:", c.version())
        print("[+] methods:", c.list_methods())
        print("[+] stats:", c.stats())
        print("[+] mutator_status:", c.mutator_status())


if __name__ == "__main__":
    main()
