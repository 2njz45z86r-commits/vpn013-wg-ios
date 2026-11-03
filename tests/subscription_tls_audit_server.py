"""Disposable loopback TLS server; writes only sanitized handshake outcomes."""
import pathlib
import socket
import ssl
import sys

root = pathlib.Path(sys.argv[1])
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(root / "cert.pem", root / "key.pem")
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(1)
    (root / "port").write_text(str(server.getsockname()[1]), encoding="ascii")
    events = []
    while not (root / "stop").exists():
        try:
            connection, _ = server.accept()
            connection.settimeout(10)
            stage = (root / "stage").read_text(encoding="ascii").strip()
            if stage not in ("downloader", "default"):
                raise RuntimeError("invalid synthetic test stage")
            try:
                with context.wrap_socket(connection, server_side=True) as secured:
                    events.append(stage + ":accepted")
                    secured.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (ssl.SSLError, OSError):
                events.append(stage + ":rejected")
        except socket.timeout:
            continue
    (root / "outcomes").write_text("\n".join(events) + "\n", encoding="ascii")
