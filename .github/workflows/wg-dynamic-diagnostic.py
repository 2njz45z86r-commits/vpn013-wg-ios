"""Disposable loopback test; never reads production credentials or contacts VPN servers."""
import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

binary = sys.argv[1]

def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

api, forward, udp = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_STREAM), free_port(socket.SOCK_DGRAM)
echo = socket.socket()
echo.bind(('127.0.0.1', 0))
echo.listen()
echo_port = echo.getsockname()[1]

def echo_loop():
    while True:
        try:
            conn, _ = echo.accept()
            with conn:
                while data := conn.recv(1024):
                    conn.sendall(data)
        except OSError:
            return

threading.Thread(target=echo_loop, daemon=True).start()
base = {'log': {'loglevel': 'warning'},
        'api': {'tag': 'api', 'services': ['HandlerService']},
        'inbounds': [
            {'tag':'rpc', 'listen':'127.0.0.1', 'port':api, 'protocol':'dokodemo-door', 'settings':{'address':'127.0.0.1'}},
            {'tag':'existing', 'listen':'127.0.0.1', 'port':forward, 'protocol':'dokodemo-door', 'settings':{'address':'127.0.0.1','port':echo_port,'network':'tcp'}}],
        'outbounds':[{'protocol':'freedom','tag':'direct'}],
        'routing':{'rules':[{'type':'field','inboundTag':['rpc'],'outboundTag':'api'}]}}
wg = {'inbounds':[{'tag':'disposable-wg', 'listen':'127.0.0.1', 'port':udp, 'protocol':'wireguard',
                   'settings':{'secretKey':base64.b64encode(os.urandom(32)).decode(), 'noKernelTun':True, 'peers':[]}}]}

with tempfile.TemporaryDirectory(prefix='wg-dynamic-') as d:
    os.chmod(d, 0o700)
    config, add = Path(d)/'base.json', Path(d)/'add.json'
    config.write_text(json.dumps(base)); add.write_text(json.dumps(wg))
    proc = subprocess.Popen([binary, 'run', '-c', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            if proc.poll() is not None:
                raise RuntimeError('Xray exited before loopback listeners started')
            try:
                test = socket.create_connection(('127.0.0.1', forward), timeout=.3)
                break
            except OSError:
                time.sleep(.1)
        else:
            raise RuntimeError('loopback listener not ready')
        with test:
            test.settimeout(3)
            def exchange(value):
                test.sendall(value)
                if test.recv(len(value)) != value:
                    raise RuntimeError('existing connection did not survive')
            exchange(b'before')
            subprocess.run([binary, 'api', 'adi', f'--server=127.0.0.1:{api}', str(add)], check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if proc.poll() is not None:
                raise RuntimeError('process restarted or exited')
            exchange(b'after-add')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                try:
                    s.bind(('127.0.0.1', udp))
                except OSError:
                    pass
                else:
                    raise RuntimeError('WireGuard UDP socket not bound')
            subprocess.run([binary, 'api', 'rmi', f'--server=127.0.0.1:{api}', 'disposable-wg'], check=True, timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if proc.poll() is not None:
                raise RuntimeError('process restarted or exited on removal')
            exchange(b'after-remove')
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.bind(('127.0.0.1', udp))
        print(json.dumps({'synthetic_local_only':True,'dynamic_add_remove':True,'existing_tcp_connection_survived':True,'xray_process_unchanged':True,'udp_released':True,'handshake_tested':False,'panel_tested':False,'production_changed':False}))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill(); proc.wait()
        echo.close()
