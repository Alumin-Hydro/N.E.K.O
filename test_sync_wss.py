# Test sync socket WSS through proxy
import socket, ssl, base64, os, hashlib

host = "gateway.discord.gg"
port = 443
proxy_host = "127.0.0.1"
proxy_port = 7890

print(f"[1] TCP connect to proxy {proxy_host}:{proxy_port}...")
sock = socket.create_connection((proxy_host, proxy_port), timeout=10)
print("[1] OK")

print(f"[2] HTTP CONNECT to {host}:{port}...")
connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
sock.sendall(connect_req.encode())
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = sock.recv(4096)
    if not chunk:
        raise RuntimeError("Proxy closed during CONNECT")
    resp += chunk
status = resp.split(b"\r\n")[0].decode()
print(f"[2] {status}")
if b"200" not in status.encode():
    raise RuntimeError(f"CONNECT failed: {status}")

print("[3] TLS handshake...")
ctx = ssl.create_default_context()
tls = ctx.wrap_socket(sock, server_hostname=host)
print("[3] OK")

print("[4] WebSocket handshake...")
key = base64.b64encode(os.urandom(16)).decode()
req = (
    f"GET /?v=10&encoding=json HTTP/1.1\r\n"
    f"Host: {host}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    f"Sec-WebSocket-Key: {key}\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
tls.sendall(req.encode())
resp = b""
while b"\r\n\r\n" not in resp:
    chunk = tls.recv(4096)
    if not chunk:
        raise RuntimeError("Closed during WS handshake")
    resp += chunk
status = resp.split(b"\r\n")[0].decode()
print(f"[4] {status}")
if b"101" not in status.encode():
    raise RuntimeError(f"WS upgrade failed: {status}")

print("[5] Reading Hello frame...")
hdr = tls.recv(2)
b1, b2 = hdr[0], hdr[1]
ln = b2 & 0x7F
if ln == 126:
    ln = int.from_bytes(tls.recv(2), "big")
elif ln == 127:
    ln = int.from_bytes(tls.recv(8), "big")
payload = b""
while len(payload) < ln:
    chunk = tls.recv(ln - len(payload))
    if not chunk:
        raise RuntimeError("Closed during Hello")
    payload += chunk
print(f"[5] Hello: {payload.decode()}")

print("\nALL OK - sync socket works through proxy")
tls.close()
