# create_users.py
from firebase_init import init_firebase
from crypto_utils import generate_salt, derive_verifier, to_hex
from firebase_admin import firestore
import time

db = init_firebase()
USERS_COLLECTION = "users"

print("Comenzando el registro de 300 usuarios...")

# Parámetros para la generación masiva
NUM_USERS = 300
BASE_PASSWORD = "testpass"
# Usamos una sola contraseña para simplificar el Locustfile

for i in range(1, NUM_USERS + 1):
    username = f"user{i}"
    password = BASE_PASSWORD 
    
    user_ref = db.collection(USERS_COLLECTION).document(username)
    
    # Comprobar si el usuario ya existe
    if user_ref.get().exists:
        # print(f"Usuario existe: {username}. Saltando.")
        continue
    
    try:
        salt = generate_salt()
        verifier = derive_verifier(password, salt)
        
        user_ref.set({
            "salt": to_hex(salt), 
            "verifier": to_hex(verifier), 
            "created_at": firestore.SERVER_TIMESTAMP
        })
        print(f"✅ Creado: {username}")
        # Pequeña pausa para no saturar los límites de escritura de la base de datos
        time.sleep(0.01) 
        
    except Exception as e:
        print(f"❌ Error al crear {username}: {e}")

print("Proceso de registro de usuarios finalizado.")