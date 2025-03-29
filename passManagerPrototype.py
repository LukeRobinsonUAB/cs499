import hashlib
import os
import json
import base64
from cryptography.fernet import Fernet

#Files
CREDENTIALS_FILE = "passwords.json"
#will remove master password file. much refactoring to come found better ways.
MASTER_PASSWORD_FILE = "master_password.json"

#Hashes a password using SHA-256 to create a key for encryption and returns it.
def hash_password(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

#Encrypt pass using the hashed master password as the key.
def encrypt_password(password: str, key: bytes) -> str:
    cipher = Fernet(base64.urlsafe_b64encode(key[:32]))
    return cipher.encrypt(password.encode()).decode()

#Decrypts the password using the hashed master password as the key. logical mistake here? dont save the hashed password that we use to decypt in file
def decrypt_password(encrypted_password: str, key: bytes) -> str:
    try:
        cipher = Fernet(base64.urlsafe_b64encode(key[:32]))  # Use first 32 bytes of the hash as key for Fernet
        decrypted_password = cipher.decrypt(encrypted_password.encode()).decode()
        return decrypted_password
    except InvalidToken:
        print("Error: The decryption key is incorrect or the data has been tampered with.")
        return None

#Sets a hashed master password if not already set.
def set_master_password():
    if os.path.exists(MASTER_PASSWORD_FILE):
        return  #Master password exists
    
    master_password = input("Set a master password: ")
    hashed_master_password = hash_password(master_password) #maybe just have hashed_master_password as a global
    
    with open(MASTER_PASSWORD_FILE, "w") as file:
        json.dump({"hashed_master_password": hashed_master_password.hex()}, file)

#Verifies if the entered master password is correct.
def verify_master_password(password: str) -> bool:
    if not os.path.exists(MASTER_PASSWORD_FILE):
        return False
    
    with open(MASTER_PASSWORD_FILE, "r") as file:
        master_data = json.load(file)
    
    stored_hash = bytes.fromhex(master_data["hashed_master_password"])
    computed_hash = hash_password(password)
    return computed_hash == stored_hash

#save service, username, etc
def save_credentials(service: str, username: str, password: str, master_key: bytes):
    encrypted_password = encrypt_password(password, master_key)
    
    credentials = load_credentials()
    credentials[service] = {
        "username": username,
        "password": encrypted_password
    }
    
    with open(CREDENTIALS_FILE, "w") as file:
        json.dump(credentials, file, indent=4)

#load creds
def load_credentials() -> dict:
    if os.path.exists(CREDENTIALS_FILE):
        with open(CREDENTIALS_FILE, "r") as file:
            return json.load(file)
    return {}

#return list of services
def get_services() -> list:
    credentials = load_credentials()
    return list(credentials.keys())

#display list of services, usernames, passwords
#I think in future just make it decrypt with provided master key. if user enters wrong master password it will just decypt into wrong values?
def display_all_credentials(master_key: bytes):
    credentials = load_credentials()
    if not credentials:
        print("No credentials stored.")
        return
    
    print("Stored Credentials:")
    for service, data in credentials.items():
        decrypted_password = decrypt_password(data['password'], master_key)
        print(f"Service: {service}, Username: {data['username']}, Password: {decrypted_password}")

def main():
    set_master_password()
    master_password = input("Enter master password: ")
    
    '''
    if not verify_master_password(master_password):
        print("Incorrect master password! Exiting.")
        return
    '''

    global master_key
    master_key = hash_password(master_password)  #Use the hash of the master password as the key
    
    while True:
        print("\nOptions:")
        print("1. View stored services")
        print("2. View credentials (requires master password)")
        print("3. Add a new credential")
        print("4. Exit")
        choice = input("Select an option: ")
        
        if choice == "1":
            print("Stored services:", get_services())
        elif choice == "2":
            display_all_credentials(master_key)
        elif choice == "3":
            service = input("Enter service name: ")
            username = input("Enter username: ")
            password = input("Enter password: ")
            save_credentials(service, username, password, master_key)
            print("Credential saved!")
        elif choice == "4":
            break
        else:
            print("Invalid choice, please try again.")

if __name__ == "__main__":
    main()
