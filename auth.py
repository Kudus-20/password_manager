import os
import json 
import base64
import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

AUTH_FILE = "auth_data.json"

def generate_salt():
    return os.urandom(16)

def hash_password(password: str, salt: bytes)-> str:
    kdf = PBKDF2HMAC( algorithm=hashes.SHA256(), length=32, salt=salt, iterations=10000, backend=default_backend)
    return base64.urlsafe_b64encode(kdf.derive(password.encode())).decode()

def set_up_master_password():
    print('set up your Master Password \n')
    password = getpass.getpass("Enter new Master Password: ")
    confirm = getpass.getpass("Confirm your Master Password: \n")

    if password != confirm:
        print("Passwords do not match. Please try again! \n")
        set_up_master_password()

    salt=generate_salt()
    hashed = hash_password(password, salt)

    with open(AUTH_FILE, "w") as f:
        json.dump({
            "salt" : base64.b64encode(salt).decode(),
            "hash" : hashed
        }, f)

    print("Master Password Set Up complete! \n")



def verify_master_password():
    if not os.path.exists(AUTH_FILE):
        print("No master password set. Please set one up first \n")
        set_up_master_password()
        return True
    
    with open(AUTH_FILE, "r") as f:
        data= json.load(f)

    salt = base64.b64decode(data["salt"])
    stored_hash = data["hash"]


    print("Login")

    password = getpass.getpass("Enter Master Password: \n")
    hashed_input = hash_password(password, salt)

    if hashed_input == stored_hash:
        print("Access granted!")
        return True
    else:
        print("Incorrect password. Please try again \n")
        return False
    





