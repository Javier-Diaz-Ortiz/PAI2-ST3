# firebase_init.py
import firebase_admin
from firebase_admin import credentials, firestore
import os

def init_firebase(service_account_path: str = "serviceAccountKey.json"):
    if not firebase_admin._apps:
        cred = credentials.Certificate(service_account_path)
        firebase_admin.initialize_app(cred)
    return firestore.client()
