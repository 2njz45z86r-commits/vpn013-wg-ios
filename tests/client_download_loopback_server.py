"""Send an incomplete synthetic HTTP response to one loopback-only client."""
import json
from pathlib import Path
import socket
import sys

port_path, result_path = map(Path, sys.argv[1:3])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(30)
    port_path.write_text(str(listener.getsockname()[1]), encoding="ascii")
    with listener.accept()[0] as connection:
        connection.settimeout(25)
        request = b""
        while b"\r\n\r\n" not in request and len(request) < 16384:
            chunk = connection.recv(4096)
            if not chunk:
                raise RuntimeError("Client closed before sending request headers")
            request += chunk
        if not request.startswith(b"GET /synthetic.ipa HTTP/1."):
            raise RuntimeError("Unexpected loopback request")
        payload = b"A" * 65536
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 131072\r\nConnection: close\r\n\r\n" + payload)
        # The advertised response remains incomplete. Cancellation must close
        # the client socket without this server sending the remaining bytes.
        try:
            while connection.recv(4096):
                pass
        except ConnectionResetError:
            pass
        result_path.write_text(json.dumps({"payload_sent": len(payload), "advertised": 131072, "client_closed": True}), encoding="ascii")
