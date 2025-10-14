# locustfile.py
import socket
import ssl
import json
import random
import time
# Usamos User de Locust base, compatible con el patrón de cliente personalizado
from locust import task, between, User 

# --- CONFIGURACIÓN ---
HOST = "127.0.0.1"
PORT = 4444
SERVER_CERT = "certs/server.crt"  # Certificado del servidor
MAX_MESSAGE_LENGTH = 144

# Parámetros de la prueba de carga
NUM_USERS = 300
BASE_PASSWORD = "testpass"

# Genera la lista de 300 usuarios (user1, user2, ..., user300)
TEST_USERS = [(f"user{i}", BASE_PASSWORD) for i in range(1, NUM_USERS + 1)]
# ---------------------

# --- FUNCIONES DE CRIPTOGRAFÍA (Asegúrate de tener crypto_utils.py en el path) ---
try:
    from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex
except ImportError:
    print("ERROR: Asegúrate de que 'crypto_utils.py' está en el mismo directorio.")
    exit()

def send_recv(sock, obj):
    """Envía un objeto JSON y espera la respuesta."""
    try:
        sock.sendall(json.dumps(obj).encode())
        data = sock.recv(8192)
        if not data:
            return None
        return json.loads(data.decode())
    except socket.error as e:
        # Los errores de socket se manejan fuera para reportar la falla
        raise e 
    except json.JSONDecodeError:
        # Los errores de JSON se manejan fuera
        raise Exception("Error de decodificación JSON en la respuesta del servidor.")


def login(sock, username, password):
    """Implementa el proceso de login de 2 pasos (SRP-like)."""
    
    # Paso 1: Enviar solicitud y recibir salt/server_nonce
    resp1 = send_recv(sock, {"action":"LOGIN_STEP1", "username":username})
    if not resp1 or resp1.get("status") != "CHALLENGE":
        return resp1, None

    try:
        salt = from_hex(resp1["salt"])
        server_nonce = resp1["server_nonce"]
        verifier = derive_verifier(password, salt)
        client_nonce = gen_nonce_hex(16)
        client_hmac_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
        
        # Paso 2: Enviar client_nonce y HMAC
        resp2 = send_recv(sock, {
            "action": "LOGIN_STEP2",
            "username": username,
            "client_nonce": client_nonce,
            "hmac": to_hex(client_hmac_key)
        })
        
        if resp2 and resp2.get("status") == "OK":
            session_key = from_hex(resp2["session_key"])
            current_nonce = int(resp2["nonce"])
            
            session = {
                "username": username,
                "session_key": session_key,
                "nonce": current_nonce
            }
            return resp2, session
        
        return resp2, None
        
    except Exception as e:
        # Captura errores en la lógica criptográfica
        raise Exception(f"Error durante los pasos de login para {username}: {e}")


def send_message(sock, username, session, message):
    """Envía un mensaje usando la clave de sesión y HMAC para integridad."""
    
    session["nonce"] += 1
    nonce_val = str(session["nonce"])
    session_key = session["session_key"]
    msg_body = f"user={username}&payload={message}&nonce={nonce_val}"
    hmac_val = hmac_sha256(session_key, msg_body.encode())
    
    # Enviar la transacción al servidor
    resp = send_recv(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": message,
        "nonce": nonce_val,
        "hmac": to_hex(hmac_val)
    })
    
    if resp and resp.get("status") != "OK":
        session["nonce"] -= 1

    return resp

# --- CLASE CLIENTE (Modificada para usar TLS) ---
class SecureSocketClient:
    def __init__(self, host, port, server_cert):
        self.host = host
        self.port = port
        self.server_cert = server_cert
        self.ssock = None
        self.context = self._create_ssl_context()

    def _create_ssl_context(self):
        """Crea el contexto SSL para la conexión."""
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
        context.check_hostname = False
        return context

    def connect(self):
        """Establece la conexión TCP y la envuelve en TLS/SSL."""
        try:
            sock = socket.create_connection((self.host, self.port))
            self.ssock = self.context.wrap_socket(sock, server_hostname=self.host)
        except Exception as e:
            # Propagamos el error para que Locust lo reporte
            raise ConnectionRefusedError(f"Fallo al conectar o establecer TLS: {e}")

    def close(self):
        """Cierra la conexión."""
        if self.ssock:
            self.ssock.close()
            self.ssock = None

    # Métodos de la aplicación para Locust
    def login(self, username, password):
        return login(self.ssock, username, password)

    def send_message(self, username, session, message):
        return send_message(self.ssock, username, session, message)


# --- CLASE USUARIO LOCUST CORREGIDA ---
class SecureUser(User):
    wait_time = between(1, 2)
    host = HOST
    port = PORT
    client_class = SecureSocketClient
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # El cliente se inicializa en on_start, no en __init__ para sockets
        self.client = None 
        self.session = None 
        self.username = None

    def on_start(self):
        """Se ejecuta una vez por cada usuario virtual al inicio."""
        
        self.client = self.client_class(self.host, self.port, SERVER_CERT)
        self.username, password = random.choice(TEST_USERS)
        
        # 1. CONEXIÓN TLS (SETUP)
        try:
            start_time_conn = time.time()
            self.client.connect()
            response_time_conn = (time.time() - start_time_conn) * 1000  # ms
            
            # 2. LOGIN
            start_time_login = time.time()
            resp, session = self.client.login(self.username, password)
            response_time_login = (time.time() - start_time_login) * 1000  # ms
            
            if resp and resp.get("status") == "OK":
                self.session = session
                # Reporte de éxito de LOGIN
                self.environment.events.request.fire(
                    request_type="LOGIN", name="/login", response_time=response_time_login, response_length=len(json.dumps(resp)), exception=None
                )
            else:
                # Reporte de fallo de LOGIN
                self.environment.events.request.fire(
                    request_type="LOGIN", name="/login", response_time=response_time_login, response_length=0, exception=Exception(f"Login failed: {resp}")
                )
                self.stop() # <-- CORRECCIÓN: Llamada simple a stop()
                
        except Exception as e:
            # Reporte de fallos de CONEXIÓN o lógica criptográfica antes del LOGIN
            self.environment.events.request.fire(
                request_type="SETUP", name="/connect", response_time=0, response_length=0, exception=e
            )
            self.stop() # <-- CORRECCIÓN: Llamada simple a stop()

    @task(1)
    def send_secure_message(self):
        """Tarea principal: enviar un mensaje seguro."""
        if self.session and self.client and self.client.ssock:
            message = "mensaje de prueba locust"
            
            start_time = time.time()
            try:
                resp = self.client.send_message(self.username, self.session, message)
                response_time = (time.time() - start_time) * 1000  # ms
            
                if resp and resp.get("status") == "OK":
                    self.environment.events.request.fire(
                        request_type="MESSAGE", name="/message", response_time=response_time, response_length=len(json.dumps(resp)), exception=None
                    )
                else:
                    self.environment.events.request.fire(
                        request_type="MESSAGE", name="/message", response_time=response_time, response_length=0, exception=Exception(f"Message failed: {resp}")
                    )
            except Exception as e:
                 self.environment.events.request.fire(
                    request_type="MESSAGE", name="/message", response_time=(time.time() - start_time) * 1000, response_length=0, exception=e
                )


    def on_stop(self):
        """Se ejecuta al finalizar la sesión del usuario."""
        if self.client and self.client.ssock:
            try:
                # Envía LOGOUT
                send_recv(self.client.ssock, {"action":"LOGOUT", "username":self.username})
            except Exception:
                pass
            self.client.close()