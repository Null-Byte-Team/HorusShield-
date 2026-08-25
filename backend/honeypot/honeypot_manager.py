"""HorusShield Honeypot Manager — Fixed (resource leak fixed)"""
import socket, threading, time
from datetime import datetime
from database.db_manager import db
from utils.logger import get_logger
from utils.helpers import generate_session_id
from config import active_config as config

logger = get_logger("honeypot_manager","honeypot")

class HoneypotManager:
    def __init__(self, socketio=None):
        self.socketio = socketio
        self._running = False
        self._server_sockets = []
        self._lock = threading.Lock()

    def start(self):
        if self._running: return
        self._running = True
        if config.HONEYPOT_ENABLED:
            self._start_service("SSH",    config.HONEYPOT_SSH_PORT,    self._handle_ssh)
            self._start_service("HTTP",   config.HONEYPOT_HTTP_PORT,   self._handle_http)
            self._start_service("FTP",    config.HONEYPOT_FTP_PORT,    self._handle_ftp)
            self._start_service("Telnet", config.HONEYPOT_TELNET_PORT, self._handle_telnet)
            db.add_log("honeypot","Honeypot system activated",level="info",source="honeypot")
            logger.info("Honeypot operational")

    def stop(self):
        self._running = False
        for s in self._server_sockets:
            try: s.close()
            except Exception as e: logger.debug(f"Error closing honeypot socket: {e}")
        self._server_sockets.clear()

    def _start_service(self, name, port, handler):
        t = threading.Thread(target=self._listen, args=(name,port,handler), daemon=True)
        t.start()
        logger.info(f"{name} honeypot on port {port}")

    def _listen(self, name, port, handler):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            # nosec B104: binding to 0.0.0.0 is intentional here, not an
            # oversight — a honeypot exists specifically to catch traffic
            # from the network, not just localhost. Binding to 127.0.0.1
            # would defeat its entire purpose. This is a deliberate,
            # documented exception to the "don't bind all interfaces"
            # rule the rest of the app follows (HORUS_HOST defaults to
            # 127.0.0.1 everywhere else).
            server.bind(("0.0.0.0", port))  # nosec B104
            server.listen(5)
            server.settimeout(1.0)
            with self._lock: self._server_sockets.append(server)
        except Exception as e:
            logger.error(f"Failed to bind {name} on {port}: {e}")
            return
        while self._running:
            try:
                client, addr = server.accept()
                threading.Thread(target=handler, args=(client,addr), daemon=True).start()
            except socket.timeout: continue
            except Exception as e:
                if self._running: logger.error(f"{name} error: {e}")

    def _handle_ssh(self, client, addr):
        try:
            sid = generate_session_id()
            client.send(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n")
            data = client.recv(1024).decode('utf-8','ignore')
            self._record("ssh",addr,"handshake",payload=data,session_id=sid)
            time.sleep(1); client.send(b"login as: ")
            user = client.recv(1024).decode('utf-8','ignore').strip()
            client.send(f"{user}@horus's password: ".encode())
            pw = client.recv(1024).decode('utf-8','ignore').strip()
            self._record("ssh",addr,"login_attempt",username=user,password=pw,session_id=sid)
            time.sleep(2); client.send(b"\r\nAccess denied\r\n"); client.close()
        except Exception as e:
            logger.debug(f"SSH honeypot session ended: {e}")
            try: client.close()
            except Exception: pass

    def _handle_http(self, client, addr):
        try:
            data = client.recv(1024).decode('utf-8','ignore')
            path = data.split(' ')[1] if ' ' in data else '/'
            self._record("http",addr,"get_request",payload=path)
            resp = ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n"
                    "<html><body><h2>Admin Login</h2><form method='POST'>"
                    "User: <input name='u'><br>Pass: <input type='password' name='p'><br>"
                    "<input type='submit' value='Login'></form></body></html>")
            client.send(resp.encode()); client.close()
        except Exception as e:
            logger.debug(f"HTTP honeypot session ended: {e}")
            try: client.close()
            except Exception: pass

    def _handle_ftp(self, client, addr):
        try:
            client.send(b"220 (vsFTPd 3.0.3)\r\n"); client.recv(1024)
            client.send(b"530 Please login with USER and PASS.\r\n"); client.close()
        except Exception as e:
            logger.debug(f"FTP honeypot session ended: {e}")
            try: client.close()
            except Exception: pass

    def _handle_telnet(self, client, addr):
        try:
            client.send(b"\r\nHorus Core Node 01\r\nlogin: "); client.recv(1024)
            client.send(b"Password: "); client.recv(1024)
            client.send(b"\r\nLogin incorrect\r\n"); client.close()
        except Exception as e:
            logger.debug(f"Telnet honeypot session ended: {e}")
            try: client.close()
            except Exception: pass

    def _record(self, hp_type, addr, action, username="", password="", payload="", session_id=""):
        ip, port = addr
        logger.warning(f"Honeypot hit! {hp_type.upper()} from {ip}:{port} — {action}")
        db.add_honeypot_event(honeypot_type=hp_type,source_ip=ip,source_port=port,
                               service=hp_type,action=action,username=username,
                               password=password,payload=payload,session_id=session_id,threat_level="high")
        if action=="login_attempt":
            db.add_alert(alert_type="honeypot",title=f"🍯 Trap: {hp_type.upper()}",
                         message=f"Attacker {ip} tried {username}/{password} on {hp_type}",
                         severity="high",source="honeypot")
        if self.socketio:
            self.socketio.emit('honeypot_event',{"type":hp_type,"ip":ip,"action":action,
                                                  "timestamp":datetime.now().isoformat()})
