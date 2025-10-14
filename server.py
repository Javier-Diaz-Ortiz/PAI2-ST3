# server.py
import socket, threading, json, time, logging, ssl
from firebase_init import init_firebase
from crypto_utils import generate_salt, derive_verifier, hmac_sha256, secure_compare, gen_nonce_hex, from_hex, to_hex
from firebase_admin import firestore

# Logging
logging.basicConfig(filename="server.log", level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

HOST = "0.0.0.0"
PORT = 4444

# Firebase
db = init_firebase()
USERS_COLLECTION = "users"
MESSAGES_COLLECTION = "vpn_messages"   # <<--- colección nueva para este proyecto

# Sesión / seguridad
sessions = {}
login_attempts = {}
blocked_users = {}
MAX_FAILS = 3
BLOCK_TIME = 60

# Async storage (solo guarda el mensaje; el contador se actualiza en el hilo principal)
def _store_message_async(doc):
    try:
        db.collection(MESSAGES_COLLECTION).add(doc)
    except Exception as e:
        logging.error(f"ERROR storing message async: {e}")

# ---------------------------
# Registro de usuarios
# ---------------------------
def handle_register(conn, data):
    username = data.get("username")
    password = data.get("password")
    if not username or not password:
        conn.send(json.dumps({"status":"ERROR","msg":"Faltan credenciales"}).encode())
        return

    user_ref = db.collection(USERS_COLLECTION).document(username)
    if user_ref.get().exists:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario ya existe"}).encode())
        logging.info(f"REGISTER_FAIL user={username} reason=exists")
        return

    salt = generate_salt()
    verifier = derive_verifier(password, salt)
    # Inicializamos message_count a 0 en el registro
    user_ref.set({
        "salt": to_hex(salt),
        "verifier": to_hex(verifier),
        "created_at": firestore.SERVER_TIMESTAMP,
        "message_count": 0
    })
    conn.send(json.dumps({"status":"REGISTER_OK"}).encode())
    logging.info(f"REGISTER_OK user={username}")

# ---------------------------
# Login paso 1 (reto)
# ---------------------------
def handle_login_step1(conn, data):
    username = data.get("username")
    if not username:
        conn.send(json.dumps({"status":"ERROR","msg":"Falta username"}).encode())
        return

    # brute-force blocking
    if username in blocked_users and time.time() < blocked_users[username]:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario bloqueado temporalmente"}).encode())
        return
    if username in blocked_users:
        blocked_users.pop(username)

    udoc = db.collection(USERS_COLLECTION).document(username).get()
    if not udoc.exists:
        # respuesta genérica + registrar fallo
        entry = login_attempts.get(username, {"fails":0})
        entry["fails"] += 1
        entry["last_fail"]=time.time()
        login_attempts[username]=entry
        if entry["fails"] >= MAX_FAILS:
            blocked_users[username] = time.time()+BLOCK_TIME
            logging.warning(f"LOGIN_BLOCK user={username}")
            conn.send(json.dumps({"status":"ERROR","msg":"Usuario bloqueado por fallos"}).encode())
        else:
            conn.send(json.dumps({"status":"ERROR","msg":"Usuario o contraseña incorrectos"}).encode())
        logging.warning(f"LOGIN_FAIL user={username} reason=user_not_found")
        return

    udata = udoc.to_dict()
    salt = udata["salt"]
    server_nonce = gen_nonce_hex(16)
    sessions[username] = {"server_nonce": server_nonce, "verifier": from_hex(udata["verifier"])}
    conn.send(json.dumps({"status":"CHALLENGE","salt":salt,"server_nonce":server_nonce}).encode())

# ---------------------------
# Login paso 2 (respuesta)
# ---------------------------
def handle_login_step2(conn, data):
    username = data.get("username")
    client_nonce = data.get("client_nonce")
    hmac_hex = data.get("hmac")
    if not username or not client_nonce or not hmac_hex:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario o contraseña incorrectos"}).encode())
        return
    try:
        client_hmac = from_hex(hmac_hex)
    except Exception:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario o contraseña incorrectos"}).encode())
        return
    if username not in sessions:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario o contraseña incorrectos"}).encode())
        return

    verifier = sessions[username]["verifier"]
    server_nonce = sessions[username]["server_nonce"]
    expected = hmac_sha256(verifier, (client_nonce + server_nonce).encode())

    if secure_compare(expected, client_hmac):
        login_attempts[username] = {"fails":0, "last_fail":None}
        sessions[username].update({"client_nonce": client_nonce, "last_nonce": None})
        conn.send(json.dumps({"status":"LOGIN_OK"}).encode())
        logging.info(f"LOGIN_OK user={username}")
    else:
        entry = login_attempts.get(username, {"fails":0})
        entry["fails"] += 1
        entry["last_fail"]=time.time()
        login_attempts[username]=entry
        if entry["fails"] >= MAX_FAILS:
            blocked_users[username] = time.time()+BLOCK_TIME
            conn.send(json.dumps({"status":"ERROR","msg":"Usuario bloqueado por fallos"}).encode())
            logging.warning(f"LOGIN_BLOCK user={username}")
        else:
            conn.send(json.dumps({"status":"ERROR","msg":"Usuario o contraseña incorrectos"}).encode())
            logging.warning(f"LOGIN_FAIL user={username} reason=bad_hmac fails={entry['fails']}")

# ---------------------------
# Mensajes (transacciones)
# ---------------------------
def handle_message(conn, data):
    username = data.get("username")
    payload = data.get("payload")
    nonce = data.get("nonce")
    hmac_hex = data.get("hmac")

    if not username or not payload or not nonce or not hmac_hex:
        conn.send(json.dumps({"status":"ERROR","msg":"Petición inválida"}).encode())
        return

    try:
        received_hmac = from_hex(hmac_hex)
    except Exception:
        conn.send(json.dumps({"status":"ERROR","msg":"Petición inválida"}).encode())
        return

    if username not in sessions or "client_nonce" not in sessions[username]:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario no autenticado"}).encode())
        return

    # replay
    if sessions[username].get("last_nonce") == nonce:
        conn.send(json.dumps({"status":"ERROR","msg":"Replay detectado"}).encode())
        logging.warning(f"TRANSACTION_FAIL user={username} reason=replay_detected")
        return

    verifier = sessions[username]["verifier"]
    client_nonce = sessions[username]["client_nonce"]
    server_nonce = sessions[username]["server_nonce"]
    session_key = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
    expected = hmac_sha256(session_key, (payload + nonce).encode())

    if not secure_compare(expected, received_hmac):
        conn.send(json.dumps({"status":"ERROR","msg":"Integridad fallida"}).encode())
        logging.warning(f"TRANSACTION_FAIL user={username} reason=integrity_error")
        return

    # OK: marcar nonce, responder rápido, y persistir
    sessions[username]["last_nonce"] = nonce

    # Preparamos doc del mensaje
    try:
        doc = {
            "username": username,
            "message": payload[:144],
            "nonce": nonce,
            "hmac": to_hex(received_hmac),
            "timestamp": firestore.SERVER_TIMESTAMP
        }
    except Exception:
        conn.send(json.dumps({"status":"ERROR","msg":"Payload inválido"}).encode())
        return

    # Responder primero (mitiga timing)
    conn.send(json.dumps({"status":"MESSAGE_OK"}).encode())
    logging.info(f"MESSAGE_OK user={username} payload={payload} nonce={nonce}")

    # Guardar mensaje de forma asíncrona
    threading.Thread(target=_store_message_async, args=(doc,), daemon=True).start()

    # --- Actualizar contador de mensajes (robusto) ---
    try:
        user_ref = db.collection(USERS_COLLECTION).document(username)
        udoc = user_ref.get()
        if udoc.exists:
            udata = udoc.to_dict() or {}
            current = udata.get("message_count", 0)
            new_val = current + 1
            user_ref.update({"message_count": new_val})
            logging.info(f"USER_MSG_COUNT user={username} count={new_val}")
        else:
            # si por algún motivo el doc no existiera, lo creamos con contador = 1
            user_ref.set({"message_count": 1}, merge=True)
            logging.info(f"USER_MSG_COUNT user={username} count=1 (created)")
    except Exception as e:
        logging.error(f"ERROR updating message_count for {username}: {e}")

# ---------------------------
# Logout
# ---------------------------
def handle_logout(conn, data):
    username = data.get("username")
    if username in sessions:
        sessions.pop(username)
        conn.send(json.dumps({"status":"LOGOUT_OK"}).encode())
        logging.info(f"LOGOUT_OK user={username}")
    else:
        conn.send(json.dumps({"status":"ERROR","msg":"Usuario no tenía sesión activa"}).encode())

# ---------------------------
# Hilo por cliente
# ---------------------------
def client_thread(conn, addr):
    print(f"Conexión desde {addr}")
    try:
        while True:
            data = conn.recv(8192)
            if not data:
                break
            try:
                msg = json.loads(data.decode())
            except Exception:
                conn.send(json.dumps({"status":"ERROR","msg":"JSON inválido"}).encode())
                continue

            action = msg.get("action")
            if action == "REGISTER":
                handle_register(conn, msg)
            elif action == "LOGIN_STEP1":
                handle_login_step1(conn, msg)
            elif action == "LOGIN_STEP2":
                handle_login_step2(conn, msg)
            elif action == "MESSAGE":
                handle_message(conn, msg)
            elif action == "LOGOUT":
                handle_logout(conn, msg)
            else:
                conn.send(json.dumps({"status":"ERROR","msg":"Acción desconocida"}).encode())
    except Exception as e:
        print("Error hilo cliente:", e)
    finally:
        conn.close()

# ---------------------------
# Servidor TLS
# ---------------------------
def start_tls_server(certfile="certs/server.crt", keyfile="certs/server.key"):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # endurecimiento: desactivar TLS obsoletos
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    # cargar cert del servidor
    context.load_cert_chain(certfile=certfile, keyfile=keyfile)
    # ciphers por defecto OK para pruebas

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
        sock.bind((HOST, PORT))
        sock.listen(128)
        print(f"TLS server listening on {HOST}:{PORT}")
        while True:
            client_sock, addr = sock.accept()
            try:
                tls_conn = context.wrap_socket(client_sock, server_side=True)
                threading.Thread(target=client_thread, args=(tls_conn, addr), daemon=True).start()
            except Exception as e:
                print("TLS handshake failed:", e)
                client_sock.close()

if __name__ == "__main__":
    start_tls_server()
