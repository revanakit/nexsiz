#!/usr/bin/env python3
import socket
import sys
import time
import signal
import os

def handler(sig, frame):
    print(f"[target] received signal {sig}, exiting", flush=True)
    sys.exit(0)

signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

HOST = '127.0.0.1'
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 2121

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((HOST, PORT))
s.listen(5)
print(f"[target] listening on {HOST}:{PORT} pid={os.getpid()}", flush=True)

while True:
    try:
        conn, addr = s.accept()
        data = conn.recv(4096)
        print(f"[target] recv {len(data)} bytes from {addr}", flush=True)
        if data:
            if b'USER' in data or data.startswith(b'USER'):
                conn.sendall(b'331 Password required\r\n')
            elif b'PASS' in data:
                conn.sendall(b'230 Login successful\r\n')
            elif b'QUIT' in data:
                conn.sendall(b'221 Goodbye\r\n')
                conn.close()
            else:
                conn.sendall(b'220 Simple Test Server Ready\r\n')
        conn.close()
    except Exception as e:
        print(f"[target] error: {e}", flush=True)
        time.sleep(0.1)
