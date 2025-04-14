import json
import os
from auth import set_up_master_password, verify_master_password
from crypto_utils import encrypt_data, decrypt_data

VAULT_FILE = "storage.json"

def load_vault():
    # create a new one
    if not os.path.exists(VAULT_FILE):
        return {}
    # open existing vault
    with open(VAULT_FILE, "r") as f:
        return json.load(f)

def save_vault(vault):
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=4)

def main():
    # Welcome message
    print("Hi! Welcome to the password vault.\n")

    # Authenticate user
    if not os.path.exists("auth_data.json"):
        set_up_master_password()

    while not verify_master_password():
        pass  # Loop until correct password

    print("\nAccessing vault...\n")

    while True:
        print("Menu: ")
        print("1. Create and save a new password")
        print("2. Retrieve password")
        print("3. Retrieve all passwords")
        print("4. Delete password")
        print("5. Exit\n")

        try:
            selection = int(input("Enter your choice: "))
        except ValueError:
            print("Please enter a number.")
            continue

        if selection == 1:
            add_to_vault()
        elif selection == 2:
            retrieve_password()
        elif selection == 3:
            retrieve_all()
        elif selection == 4:
            delete_password()
        elif selection == 5:
            print("Goodbye.")
            break
        else:
            print("Error. Choose a valid option")

def add_to_vault():
    service = input("Enter service name: ").lower()
    username = input("Enter username: ")
    password = input("Enter password: ")

    vault = load_vault()

    encrypted_username = encrypt_data(username)
    encrypted_password = encrypt_data(password)

    vault[service] = {
        "username": encrypted_username,
        "password": encrypted_password
    }

    save_vault(vault)
    print(f"{service} credentials saved!\n")

def retrieve_password():
    service = input("Enter service name to retrieve: ").lower()
    vault = load_vault()

    if service not in vault:
        print("No credentials found for this service.\n")
        return

    encrypted_data = vault[service]
    username = decrypt_data(encrypted_data["username"])
    password = decrypt_data(encrypted_data["password"])

    print(f"\nService: {service}")
    print(f"Username: {username}")
    print(f"Password: {password}\n")

def retrieve_all():
    vault = load_vault()

    if not vault:
        print("Vault is empty.\n")
        return

    print("\nStored credentials:")
    for service, creds in vault.items():
        username = decrypt_data(creds["username"])
        password = decrypt_data(creds["password"])
        print(f"- {service} | Username: {username}, Password: {password}")
    print("")

def delete_password():
    service = input("Enter service name to delete: ").lower()
    vault = load_vault()

    if service in vault:
        del vault[service]
        save_vault(vault)
        print(f"{service} credentials deleted.\n")
    else:
        print("Service not found in vault.\n")

# Entry point
if __name__ == "__main__":
    main()
