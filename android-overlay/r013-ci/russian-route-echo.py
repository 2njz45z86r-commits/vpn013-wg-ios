"""Ephemeral CI-only echo endpoints; the host owns both temporary /32 aliases."""
import socketserver,threading,time
class Echo(socketserver.BaseRequestHandler):
 def handle(self):
  self.request.settimeout(2)
  if self.request.recv(64)==b"vpn013-route-check\n":self.request.sendall(b"vpn013-route-ok\n")
servers=[]
for ip in ("2.56.24.1","198.18.0.1"):
 server=socketserver.ThreadingTCPServer((ip,13013),Echo);server.daemon_threads=True;servers.append(server)
 threading.Thread(target=server.serve_forever,daemon=True).start()
print("Local CI echo endpoints ready",flush=True)
while True:time.sleep(60)
