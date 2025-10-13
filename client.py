# client.py
import socket, ssl, json, getpass
from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex

HOST = "127.0.0.1"
PORT = 4444
SERVER_CERT = "certs/server.crt"   # used as truststore for testing

def send_recv(sock, obj):
    sock.send(json.dumps(obj).encode())
    data = sock.recv(8192)
    if not data:
        return None
    return json.loads(data.decode())

def register(sock, username, password):
    return send_recv(sock, {"action":"REGISTER","username":username,"password":password})

def login(sock, username, password):
    resp1 = send_recv(sock, {"action":"LOGIN_STEP1","username":username})
    if not resp1 or resp1.get("status") != "CHALLENGE":
        return resp1, None
    salt = from_hex(resp1["salt"]); server_nonce = resp1["server_nonce"]
    verifier = derive_verifier(password, salt)
    client_nonce = gen_nonce_hex(16)
    client_hmac = hmac_sha256(verifier, (client_nonce + server_nonce).encode())
    resp2 = send_recv(sock, {"action":"LOGIN_STEP2","username":username,"client_nonce":client_nonce,"hmac": to_hex(client_hmac)})
    if resp2 and resp2.get("status") == "LOGIN_OK":
        return resp2, {"verifier":verifier,"client_nonce":client_nonce,"server_nonce":server_nonce}
    return resp2, None

def send_message(sock, username, session, message):
    nonce = gen_nonce_hex(8)
    session_key = hmac_sha256(session["verifier"], (session["client_nonce"] + session["server_nonce"]).encode())
    hmac_val = hmac_sha256(session_key, (message + nonce).encode())
    return send_recv(sock, {"action":"MESSAGE","username":username,"payload":message,"nonce":nonce,"hmac":to_hex(hmac_val)})

if __name__ == "__main__":
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    # For self-signed test: do not check hostname
    context.check_hostname = False
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print("Conectado TLS al servidor")
            while True:
                cmd = input("cmd (register/login/msg/logout/quit): ").strip().lower()
                if cmd == "register":
                    u = input("username: "); p = getpass.getpass("password: "); print(register(ssock,u,p))
                elif cmd == "login":
                    u = input("username: "); p = getpass.getpass("password: "); resp, session = login(ssock,u,p); print(resp)
                elif cmd == "msg":
                    if 'session' in locals() and session:
                        msg = input("message (<=144 chars): ")
                        print(send_message(ssock, session.get("username", u), session, msg))
                    else:
                        print("Haz login primero")
                elif cmd == "logout":
                    print(send_recv(ssock, {"action":"LOGOUT","username":u}))
                    session = None
                elif cmd in ("quit","q","exit"):
                    break
                else:
                    print("Comando desconocido")
