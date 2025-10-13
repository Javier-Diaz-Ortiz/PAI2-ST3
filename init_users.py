# init_users.py
from firebase_init import init_firebase
from crypto_utils import generate_salt, derive_verifier, to_hex
from firebase_admin import firestore

db = init_firebase()
USERS_COLLECTION = "users"

preusers = [
    ("alice", "alicepass"),
    ("bob", "bobpass"),
    ("carol", "carolpass")
]

for u,p in preusers:
    user_ref = db.collection(USERS_COLLECTION).document(u)
    if user_ref.get().exists:
        print("User exists:", u)
        continue
    salt = generate_salt()
    verifier = derive_verifier(p, salt)
    user_ref.set({"salt": to_hex(salt), "verifier": to_hex(verifier), "created_at": firestore.SERVER_TIMESTAMP})
    print("Created:", u)
