# locustfile.py (CORREGIDO)
import socket
import ssl
import json
import random
import time
from locust import task, between, User, events

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
        # Los errores de socket se propagan para que Locust los capture
        raise e
    except json.JSONDecodeError:
        raise Exception("Error de decodificación JSON en la respuesta del servidor.")


def login(sock, username, password):
    """Implementa el proceso de login de 2 pasos (SRP-like)."""
    # Paso 1
    resp1 = send_recv(sock, {"action":"LOGIN_STEP1", "username":username})
    if not resp1 or resp1.get("status") != "CHALLENGE":
        # Si el login falla (p.ej. usuario bloqueado), devolvemos el error
        return resp1, None

    try:
        salt = from_hex(resp1["salt"])
        server_nonce = resp1["server_nonce"]
        verifier = derive_verifier(password, salt)
        client_nonce = gen_nonce_hex(16)
        client_hmac_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
        
        # Paso 2
        resp2 = send_recv(sock, {
            "action": "LOGIN_STEP2",
            "username": username,
            "client_nonce": client_nonce,
            "hmac": to_hex(client_hmac_key)
        })
        
        # -----------------------------------------------------------------
        # MODIFICACIÓN 1: Esperar "LOGIN_OK" en lugar de "OK"
        # -----------------------------------------------------------------
        if resp2 and resp2.get("status") == "LOGIN_OK":
            
            # -----------------------------------------------------------------
            # MODIFICACIÓN 2: Calcular la clave de sesión en el cliente
            # (Igual que en el server.py, línea 197)
            # -----------------------------------------------------------------
            session_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
            
            # MODIFICACIÓN 3: Inicializar el nonce en el cliente
            current_nonce = 0 
            
            session = {
                "username": username,
                "session_key": session_key, # Usamos la clave calculada
                "nonce": current_nonce      # Usamos el nonce inicializado
            }
            return resp2, session
        
        # Si el login falla en el paso 2
        return resp2, None
        
    except Exception as e:
        raise Exception(f"Error durante los pasos de login para {username}: {e}")


def send_message(sock, session, message):
    """Envía un mensaje usando la clave de sesión y HMAC para integridad."""
    
    session["nonce"] += 1
    nonce_val = str(session["nonce"])
    session_key = session["session_key"]
    username = session["username"]
    
    # -----------------------------------------------------------------
    # MODIFICACIÓN 4: Calcular el HMAC igual que el servidor
    # (server.py, línea 199)
    # -----------------------------------------------------------------
    msg_body_to_sign = (message + nonce_val).encode()
    hmac_val = hmac_sha256(session_key, msg_body_to_sign)
    
    # Enviar la transacción al servidor
    resp = send_recv(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": message,
        "nonce": nonce_val,
        "hmac": to_hex(hmac_val)
    })
    
    # -----------------------------------------------------------------
    # MODIFICACIÓN 5: Esperar "MESSAGE_OK" en lugar de "OK"
    # -----------------------------------------------------------------
    if resp and resp.get("status") != "MESSAGE_OK":
        # Si falla, revertimos el nonce para reintentar
        session["nonce"] -= 1

    return resp

# --- CLASE CLIENTE ---
class SecureSocketClient:
    def __init__(self, host, port, server_cert):
        self.host = host
        self.port = port
        self.server_cert = server_cert
        self.ssock = None
        self.context = self._create_ssl_context()

    def _create_ssl_context(self):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=self.server_cert)
        context.check_hostname = False
        return context

    def connect(self):
        try:
            sock = socket.create_connection((self.host, self.port))
            self.ssock = self.context.wrap_socket(sock, server_hostname=self.host)
        except Exception as e:
            # Importante: cerrar el socket base si wrap_socket falla
            if 'sock' in locals():
                sock.close()
            self.ssock = None
            raise ConnectionRefusedError(f"Fallo al conectar o establecer TLS: {e}")

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
                pass # Ignorar errores al hacer logout


# --- CLASE USUARIO LOCUST OPTIMIZADA ---
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
        self.client = SecureSocketClient(self.host, self.port, SERVER_CERT)
        self.username, self.password = random.choice(TEST_USERS)
        self.session = None # El usuario empieza sin sesión


    @task
    def login_and_send_message(self):
        """
        Tarea principal: 
        1. Si no tiene sesión, intenta conectar y loguear.
        2. Si tiene sesión, envía un mensaje.
        """
        
        try:
            # --- 1. SI NO TIENE SESIÓN, INTENTA CONECTAR Y LOGUEAR ---
            if not self.session:
                start_time = time.time()
                try:
                    # Conectar y Loguear
                    resp, session = self.client.login(self.username, self.password)
                    response_time = (time.time() - start_time) * 1000
                    
                    if session:
                        # Éxito de Login
                        self.session = session
                        self.environment.events.request.fire(
                            request_type="LOGIN", name="/login", response_time=response_time, response_length=len(json.dumps(resp)), exception=None
                        )
                    else:
                        # Fallo de Login (controlado por el servidor)
                        raise Exception(f"Login failed: {resp}")

                except Exception as e:
                    # Fallo de conexión o login
                    response_time = (time.time() - start_time) * 1000
                    self.environment.events.request.fire(
                        request_type="LOGIN", name="/login", response_time=response_time, response_length=0, exception=e
                    )
                    self.client.close() # Cierra el socket si el login falla
                    return # No continúa a "send_message"

            # --- 2. SI TIENE SESIÓN, ENVÍA MENSAJE ---
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
                # Si falla el mensaje (p.ej. se cae el servidor), cerramos socket y reseteamos sesión
                # para forzar un nuevo login en la siguiente iteración.
                self.client.close()
                self.session = None

        except Exception as e:
            # Captura errores inesperados
            events.request.fire(request_type="TASK", name="UnhandledException", response_time=0, response_length=0, exception=e)
            # Resetea el estado del usuario
            self.client.close()
            self.session = None


    def on_stop(self):
        """Se ejecuta al finalizar la sesión del usuario."""
        if self.client and self.session:
            self.client.logout(self.username)
        if self.client:
            self.client.close()