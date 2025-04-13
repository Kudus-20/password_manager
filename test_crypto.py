from crypto_utils import encrypt_data, decrypt_data

sample_text = "mySuperSecretPassword123!"

encrypted = encrypt_data(sample_text)
print(f"Encrypted: {encrypted}")

decrypted = decrypt_data(encrypted)
print(f"Decrypted: {decrypted}")

if decrypted == sample_text:
    print("Success: Decrypted text matches original!")
else:
    print("Error: Decrypted text does NOT match original.")
