from cryptography.fernet import Fernet
import os

# key= Fernet.generate_key()
# f= Fernet(key)

# token = f.encrypt("Hello".encode())

# original = f.decrypt((token).decode())

KEY_FILE= "key.key"

def generate_key():
    key= Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()

    with open(KEY_FILE, "rb") as f:
        return f.read()
    
def encrypt_data(data):
    key=load_key()
    fernet= Fernet(key)
    encrypted_data = fernet.encrypt(data.encode())

    return encrypted_data.decode()

def decrypt_data(ciphertext):
    key= load_key()
    fernet= Fernet(key)
    decrypted_data= fernet.decrypt(ciphertext.encode())
    return decrypted_data.decode()