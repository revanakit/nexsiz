#!/usr/bin/env python3
"""
Nexsiz test target: minimal FTP-like server that can crash on demand.
Crash triggers:
  - payload containing b'CRASH'  -> os._exit(1) / SIGSEGV-like
  - payload containing b'ABORT'  -> raise SystemExit
  - payload containing b'HANG'   -> sleep forever
Used for snapshot/process-restore and coverage SHM validation.
"""
import socket
import sys
import time
import signal
import os
import struct

def handler(sig, frame):
    print(f"[target] signal {sig} received, pid={os.getpid()} exiting", flush=True)
    sys.exit(0)

signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

HOST = '127.0.0.1'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2121
PIDFILE = sys.argv[2] if len(sys.argv) > 2 else None

if PIDFILE:
    with open(PIDFILE, 'w') as f:
        f.write(str(os.getpid()))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(8)
print(f"[target] listening on {HOST}:{PORT} pid={os.getpid()}", flush=True)

crash_count = 0
while True:
    try:
        conn, addr = s.accept()
        data = conn.recv(8192)
        print(f"[target] recv {len(data)}B from {addr} pid={os.getpid()}", flush=True)
        if not data:
            conn.close()
            continue

        # Crash triggers for snapshot testing
        if b'CRASH' in data:
            crash_count += 1
            print(f"[target] CRASH trigger #{crash_count} — exiting hard", flush=True)
            conn.close()
            os._exit(1)  # hard exit, no cleanup
        if b'ABORT' in data:
            print(f"[target] ABORT trigger — SystemExit", flush=True)
            conn.close()
            raise SystemExit(2)
        if b'HANG' in data:
            print(f"[target] HANG trigger — sleeping forever", flush=True)
            time.sleep(3600)

        # Minimal FTP-ish responses
        if data.startswith(b'USER') or b'USER' in data:
            conn.sendall(b'331 Password required\r\n')
        elif data.startswith(b'PASS') or b'PASS' in data:
            conn.sendall(b'230 Login successful\r\n')
        elif data.startswith(b'QUIT') or b'QUIT' in data:
            conn.sendall(b'221 Goodbye\r\n')
        elif data.startswith(b'SYST'):
            conn.sendall(b'215 UNIX Type: L8\r\n')
        else:
            conn.sendall(b'220 Crashable Test Server Ready\r\n')
        conn.close()
    except SystemExit:
        raise
    except Exception as e:
        print(f"[target] error: {e}", flush=True)
        time.sleep(0.05)
