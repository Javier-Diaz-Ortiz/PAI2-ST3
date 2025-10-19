# locustfilesintls.py (SIN TLS, APUNTA A PUERTO 4443)
import socket
# MODIFICACIÓN: Se ha quitado 'import ssl'
import json
import random
import time
from locust import task, between, User, events

# --- CONFIGURACIÓN ---
HOST = "127.0.0.1"
# MODIFICACIÓN: Cambiado el puerto para la prueba
PORT = 4443 
# MODIFICACIÓN: Eliminada la variable SERVER_CERT

MAX_MESSAGE_LENGTH = 144
NUM_USERS = 300
BASE_PASSWORD = "testpass"
TEST_USERS = [(f"user{i}", BASE_PASSWORD) for i in range(1, NUM_USERS + 1)]
# ---------------------

# --- (Las funciones de cripto, send_recv, login, y send_message son idénticas) ---
try:
    from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex
except ImportError:
    print("ERROR: Asegúrate de que 'crypto_utils.py' está en el mismo directorio.")
    exit()

def send_recv(sock, obj):
    try:
        sock.sendall(json.dumps(obj).encode())
        data = sock.recv(8192)
        if not data:
            return None
        return json.loads(data.decode())
    except socket.error as e:
        raise e
    except json.JSONDecodeError:
        raise Exception("Error de decodificación JSON en la respuesta del servidor.")

def login(sock, username, password):
    resp1 = send_recv(sock, {"action":"LOGIN_STEP1", "username":username})
    if not resp1 or resp1.get("status") != "CHALLENGE":
        return resp1, None
    try:
        salt = from_hex(resp1["salt"])
        server_nonce = resp1["server_nonce"]
        verifier = derive_verifier(password, salt)
        client_nonce = gen_nonce_hex(16)
        client_hmac_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
        
        resp2 = send_recv(sock, {
            "action": "LOGIN_STEP2",
            "username": username,
            "client_nonce": client_nonce,
            "hmac": to_hex(client_hmac_key)
        })
        
        if resp2 and resp2.get("status") == "LOGIN_OK":
            session_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
            current_nonce = 0 
            session = {
                "username": username,
                "session_key": session_key,
                "nonce": current_nonce
            }
            return resp2, session
        return resp2, None
    except Exception as e:
        raise Exception(f"Error durante los pasos de login para {username}: {e}")

def send_message(sock, session, message):
    session["nonce"] += 1
    nonce_val = str(session["nonce"])
    session_key = session["session_key"]
    username = session["username"]
    
    msg_body_to_sign = (message + nonce_val).encode()
    hmac_val = hmac_sha256(session_key, msg_body_to_sign)
    
    resp = send_recv(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": message,
        "nonce": nonce_val,
        "hmac": to_hex(hmac_val)
    })
    
    if resp and resp.get("status") != "MESSAGE_OK":
        session["nonce"] -= 1
    return resp

# --- CLASE CLIENTE (Modificada) ---
class SecureSocketClient:
    # MODIFICACIÓN: Eliminado 'server_cert' del constructor
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.ssock = None
        # MODIFICACIÓN: Eliminado 'self.context' y la llamada a _create_ssl_context

    # MODIFICACIÓN: Eliminada toda la función '_create_ssl_context'

    def connect(self):
        try:
            # MODIFICACIÓN: Se crea el socket y se asigna directamente a self.ssock
            sock = socket.create_connection((self.host, self.port))
            self.ssock = sock 
        except Exception as e:
            self.ssock = None
            # MODIFICACIÓN: Mensaje de error simplificado
            raise ConnectionRefusedError(f"Fallo al conectar (NO-TLS): {e}")

    def close(self):
        if self.ssock:
            try:
                self.ssock.close()
            except Exception:
                pass
            self.ssock = None

    def login(self, username, password):
        if not self.ssock:
            self.connect()
        return login(self.ssock, username, password)

    def send_message(self, session, message):
        if not self.ssock:
            raise Exception("Socket no conectado para enviar mensaje")
        return send_message(self.ssock, session, message)
    
    def logout(self, username):
        if self.ssock:
            try:
                send_recv(self.ssock, {"action":"LOGOUT", "username":username})
            except Exception:
                pass


# --- CLASE USUARIO LOCUST (Modificada) ---
class SecureUser(User):
    wait_time = between(1, 2)
    host = HOST
    port = PORT
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.client = None
        self.session = None
        self.username = None
        self.password = None

    def on_start(self):
        """Inicializa el cliente y el usuario."""
        # MODIFICACIÓN: Se crea el cliente sin el parámetro 'SERVER_CERT'
        self.client = SecureSocketClient(self.host, self.port)
        self.username, self.password = random.choice(TEST_USERS)
        self.session = None


    @task
    def login_and_send_message(self):
        try:
            if not self.session:
                start_time = time.time()
                try:
                    resp, session = self.client.login(self.username, self.password)
                    response_time = (time.time() - start_time) * 1000
                    
                    if session:
                        self.session = session
                        self.environment.events.request.fire(
                            request_type="LOGIN", name="/login", response_time=response_time, response_length=len(json.dumps(resp)), exception=None
                        )
                    else:
                        raise Exception(f"Login failed: {resp}")

                except Exception as e:
                    response_time = (time.time() - start_time) * 1000
                    self.environment.events.request.fire(
                        request_type="LOGIN", name="/login", response_time=response_time, response_length=0, exception=e
                    )
                    self.client.close()
                    return

            message = "mensaje de prueba locust"
            start_time = time.time()
            try:
                resp = self.client.send_message(self.session, message)
                response_time = (time.time() - start_time) * 1000
                
                if resp and resp.get("status") == "MESSAGE_OK":
                    self.environment.events.request.fire(
                        request_type="MESSAGE", name="/message", response_time=response_time, response_length=len(json.dumps(resp)), exception=None
                    )
                else:
                    raise Exception(f"Message failed: {resp}")

            except Exception as e:
                response_time = (time.time() - start_time) * 1000
                self.environment.events.request.fire(
                    request_type="MESSAGE", name="/message", response_time=response_time, response_length=0, exception=e
                )
                self.client.close()
                self.session = None

        except Exception as e:
            events.request.fire(request_type="TASK", name="UnhandledException", response_time=0, response_length=0, exception=e)
            self.client.close()
            self.session = None

    def on_stop(self):
        if self.client and self.session:
            self.client.logout(self.username)
        if self.client:
            self.client.close()