# test_client_extended.py
"""
Cliente de pruebas extendido (TLS) para el proyecto.
Prueba:
 - registro
 - login (challenge-response)
 - transacción válida
 - replay (reutiliza nonce/hmac)
 - MITM payload-change (usa nonce nuevo, reutiliza hmac viejo) -> integrity fail
 - MITM corrupt-hmac (nonce nuevo + hmac inválido) -> integrity fail
 - brute-force (3 intentos) -> bloqueo
 - timing test (mide tiempos OK vs BAD)
"""

import socket
import ssl
import json
import time
import statistics
from crypto_utils import derive_verifier, hmac_sha256, gen_nonce_hex, from_hex, to_hex

HOST = "127.0.0.1"
PORT = 4444
SERVER_CERT = "certs/server.crt"   # Certificado del servidor (truststore para pruebas)

def send(sock, msg):
    """Envía JSON y recibe JSON (bloqueante)."""
    try:
        sock.send(json.dumps(msg).encode())
        data = sock.recv(8192)
        if not data:
            return None
        return json.loads(data.decode())
    except Exception as e:
        print("Error send/recv:", e)
        return None

def register_user(sock, username, password):
    print(f"[+] Registrando usuario {username} ...")
    return send(sock, {"action": "REGISTER", "username": username, "password": password})

def login(sock, username, password):
    """Realiza LOGIN_STEP1 y LOGIN_STEP2. Devuelve (resp, session_dict)."""
    resp1 = send(sock, {"action": "LOGIN_STEP1", "username": username})
    if not resp1 or resp1.get("status") != "CHALLENGE":
        return resp1, None

    # salt viene como hex en resp1['salt']
    try:
        salt = from_hex(resp1["salt"])
    except Exception as e:
        print("Salt decode error:", e)
        return resp1, None

    server_nonce = resp1["server_nonce"]
    verifier = derive_verifier(password, salt)
    client_nonce = gen_nonce_hex(16)
    client_hmac = hmac_sha256(verifier, (client_nonce + server_nonce).encode())

    resp2 = send(sock, {
        "action": "LOGIN_STEP2",
        "username": username,
        "client_nonce": client_nonce,
        "hmac": to_hex(client_hmac)
    })

    if resp2 and resp2.get("status") == "LOGIN_OK":
        session = {
            "username": username,
            "verifier": verifier,
            "client_nonce": client_nonce,
            "server_nonce": server_nonce
        }
        return resp2, session
    return resp2, None

def send_message(sock, session, message):
    """Envía una transacción/mensaje autenticado."""
    username = session["username"]
    nonce = gen_nonce_hex(8)
    session_key = hmac_sha256(session["verifier"], (session["client_nonce"] + session["server_nonce"]).encode())
    hmac_val = hmac_sha256(session_key, (message + nonce).encode())

    return send(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": message,
        "nonce": nonce,
        "hmac": to_hex(hmac_val)
    }), {"payload": message, "nonce": nonce, "hmac": hmac_val}

def replay_message(sock, username, tx_data):
    """Reenvía exactamente el mismo nonce+hmac (replay)."""
    return send(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": tx_data["payload"],
        "nonce": tx_data["nonce"],
        "hmac": to_hex(tx_data["hmac"])
    })

def mitm_modify_payload(sock, username, tx_data, new_payload):
    """
    MITM: cambia payload pero usa NONCE NUEVO (para evitar que el servidor lo considere replay)
    y reutiliza HMAC viejo (attacker no puede recomputar hmac válido) -> debe fallar por integridad.
    """
    nonce_new = gen_nonce_hex(8)
    return send(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": new_payload,
        "nonce": nonce_new,
        "hmac": to_hex(tx_data["hmac"])  # antiguo, inválido para new_payload+nonce_new
    })

def mitm_modify_hmac(sock, username, tx_data):
    """
    MITM: usa nonce nuevo y hmac corrompido (ej. ceros) -> debe fallar por integridad.
    """
    nonce_new = gen_nonce_hex(8)
    fake_hmac_hex = to_hex(b"\x00" * 32)
    return send(sock, {
        "action": "MESSAGE",
        "username": username,
        "payload": tx_data["payload"],
        "nonce": nonce_new,
        "hmac": fake_hmac_hex
    })

def brute_force_fail(sock, username):
    """Intenta 3 logins fallidos para provocar bloqueo."""
    results = []
    for i in range(3):
        resp1 = send(sock, {"action": "LOGIN_STEP1", "username": username})
        if resp1 and resp1.get("status") == "CHALLENGE":
            # mandar HMAC inválido (no derivado correctamente)
            resp2 = send(sock, {
                "action": "LOGIN_STEP2",
                "username": username,
                "client_nonce": gen_nonce_hex(16),
                "hmac": "deadbeef"
            })
            results.append(resp2)
        else:
            # si CHALLENGE no llega (usuario no existe), forzamos un intento fallido genérico
            results.append(resp1)
    return results

def timing_test_message(sock, session, payload, n=30):
    """Mide RTT para mensajes correctos vs mensajes con HMAC incorrecto."""
    times_ok = []
    times_bad = []
    username = session["username"]
    for _ in range(n):
        # correcto
        nonce = gen_nonce_hex(8)
        session_key = hmac_sha256(session["verifier"], (session["client_nonce"] + session["server_nonce"]).encode())
        hmac_ok = hmac_sha256(session_key, (payload + nonce).encode())
        msg_ok = {"action":"MESSAGE","username":username,"payload":payload,"nonce":nonce,"hmac":to_hex(hmac_ok)}
        t0 = time.perf_counter()
        send(sock, msg_ok)
        t1 = time.perf_counter()
        times_ok.append(t1 - t0)

        # incorrecto (HMAC corrupto)
        nonce2 = gen_nonce_hex(8)
        msg_bad = {"action":"MESSAGE","username":username,"payload":payload,"nonce":nonce2,"hmac":to_hex(b"\x00"*32)}
        t0 = time.perf_counter()
        send(sock, msg_bad)
        t1 = time.perf_counter()
        times_bad.append(t1 - t0)

    return {"ok": times_ok, "bad": times_bad}

def main():
    # Construir contexto TLS con el certificado del servidor como CA (pruebas locales)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=SERVER_CERT)
    context.check_hostname = False  # para pruebas locales con self-signed
    # Establecer conexión TLS
    with socket.create_connection((HOST, PORT)) as sock:
        with context.wrap_socket(sock, server_hostname=HOST) as ssock:
            print("Conectado (TLS) al servidor", HOST, PORT)

            # 1) Registro
            print("\n=== REGISTER ===")
            reg = register_user(ssock, "javi", "password123")
            print(reg)

            # 2) Login
            print("\n=== LOGIN ===")
            resp, session = login(ssock, "javi", "password123")
            print("Login response:", resp)

            if resp and resp.get("status") == "LOGIN_OK":
                # 3) Transacción válida
                print("\n--- Mensaje/Transacción válida ---")
                tx_resp, tx_data = send_message(ssock, session, "Cuenta1,Cuenta2,100.0")
                print("Valid message response:", tx_resp)

                # 4) Replay (usar mismo nonce/hmac)
                print("\n--- Replay (misma nonce/hmac) ---")
                replay_resp = replay_message(ssock, "javi", tx_data)
                print("Replay response (expected 'Replay detectado'):", replay_resp)

                # 5) MITM payload-change (usando NONCE nuevo)
                print("\n--- MITM: cambiar payload (debe fallar integridad) ---")
                mitm1 = mitm_modify_payload(ssock, "javi", tx_data, "Cuenta1,Cuenta2,1000000.0")
                print("MITM payload response (expected integrity fail):", mitm1)

                # 6) MITM corrupt-hmac
                print("\n--- MITM: corromper HMAC (debe fallar integridad) ---")
                mitm2 = mitm_modify_hmac(ssock, "javi", tx_data)
                print("MITM corrupt-hmac response (expected integrity fail):", mitm2)

                # 7) Logout
                print("\n--- LOGOUT ---")
                print(send(ssock, {"action":"LOGOUT","username":"javi"}))

            # 8) Login inválido & brute force
            print("\n=== Login invalid / brute force ===")
            bad_login = login(ssock, "nonexistent_user", "whatever")
            print("Login nonexistent:", bad_login)
            print("Brute-force attempts (alice):", brute_force_fail(ssock, "alice"))

            # 9) Timing test (nuevo login para timing)
            print("\n=== Timing test ===")
            resp_t, session_t = login(ssock, "javi", "password123")
            if resp_t and resp_t.get("status") == "LOGIN_OK":
                times = timing_test_message(ssock, session_t, "C1,C2,1.0", n=30)
                ok_avg = statistics.mean(times["ok"])
                bad_avg = statistics.mean(times["bad"])
                print("Timing OK avg:", ok_avg, "s; BAD avg:", bad_avg, "s")
                print("Timing OK stdev:", statistics.stdev(times["ok"]), "BAD stdev:", statistics.stdev(times["bad"]))
            else:
                print("No se pudo obtener sesión para timing test.")

if __name__ == "__main__":
    main()
