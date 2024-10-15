import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import json
import logging
import time


# Configure logging
logging.basicConfig(
    filename='server_logs.log',  # Log file name
    level=logging.INFO,           # Set logging level which is informational here
    format='%(asctime)s - %(levelname)s - %(message)s',  # Log format
)

def log_event(message):
    logging.info(message)

# Diffie-Hellman parameters
P = 53  
G = 2   

CREDENTIALS_FILE = 'creds.txt'

# Padding function to ensure message length is a multiple of 16 bytes
def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

# Unpadding function after decryption
def unpad(data):
    return data[:-ord(data[len(data)-1:])]

# Encrypt the message using AES-128-CBC
def encrypt_message(key, message):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    padded_message = pad(message).encode('utf-8')
    encrypted = encryptor.update(padded_message) + encryptor.finalize()
    
    return base64.b64encode(iv + encrypted).decode('utf-8')

# Decrypt the message using AES-128-CBC
def decrypt_message(key, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted_message[16:]) + decryptor.finalize()
    return unpad(decrypted).decode('utf-8')

# Function to generate salt for password hashing
def generate_salt():
    return secrets.token_hex(16)

# Function to hash the password using SHA-256 with a salt
def hash_password(password, salt):
    return hashlib.sha256((password + salt).encode('utf-8')).hexdigest()

# Load credentials from a file
def load_credentials():
    if not os.path.exists(CREDENTIALS_FILE):
        return {}
    with open(CREDENTIALS_FILE, 'r') as file:
        return json.load(file)

# Save credentials to a file
def save_credentials(credentials):
    with open(CREDENTIALS_FILE, 'w') as file:
        json.dump(credentials, file)

# Handle user registration for this and decrypting data using mutual key
def handle_registration(client_socket, mutual_key, data):
    
    command, email, username, password = data.split(':')

    credentials = load_credentials()

    # Checks for email have user or not
    if email in [v['email'] for v in credentials.values()]:
        client_socket.send(encrypt_message(mutual_key, "A User Is Already Registered On This Mail").encode('utf-8'))
        log_event("A User Is Already Registered On This Mail entered by user " + username)
        return

    #Checks if this username exsists
    if username in credentials:
        client_socket.send(encrypt_message(mutual_key, "Username already exists").encode('utf-8'))
        log_event("Username already exists entered by user " + username)
        return
    
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    
    credentials[username] = {'email': email, 'password': hashed_password, 'salt': salt}
    save_credentials(credentials)
    
    client_socket.send(encrypt_message(mutual_key, "Registration successful").encode('utf-8'))
    log_event("User {} has registered successfully".format(username))

# Handle client login
def handle_login(client_socket, mutual_key1, data):

    command, username, password = data.split(':')
    
    print(f"User {username} attempting to login")
    log_event(f"User {username} attempting to login")
    
    #Check if user is valid
    #Check for username
    credentials = load_credentials()
    if username not in credentials:
        client_socket.send(encrypt_message(mutual_key1, "Invalid username").encode('utf-8'))
        log_event("Invalid username entered by user " + username)
        return
    
    stored_password = credentials[username]['password']
    salt = credentials[username]['salt']
    hashed_password = hash_password(password, salt)
    
    #check for pass
    if hashed_password == stored_password:
        client_socket.send(encrypt_message(mutual_key1, "Login successful").encode('utf-8'))
        print("User {} has logged in successfully".format(username))   
        log_event("User {} has logged in successfully".format(username))
        # Diffie-Hellman exchange for mutual key 2
        server_secret = secrets.randbelow(P)
        server_public_key = pow(G, server_secret, P)

        # Send server's public key for mutual key 2
        client_socket.send(str(server_public_key).encode('utf-8'))

        # Receive client's public key
        client_public_key = int(client_socket.recv(256).decode('utf-8'))

        # Compute shared key for mutual key 2
        shared_key = pow(client_public_key, server_secret, P)

        # Append username to shared key and generate mutual key 2
        mutual_key2 = hashlib.sha256((username + str(shared_key)).encode('utf-8')).digest()[:16]
    
        print(f"Mutual Key 2: {mutual_key2.hex()}")
        log_event(f"Mutual Key 2 created for post-auth")

        # Continue to handle chat messages
        handle_chat(client_socket, mutual_key2)

    #in case pass is not correct
    else:
        client_socket.send(encrypt_message(mutual_key1, "Invalid password").encode('utf-8'))
        log_event("Invalid password entered By User " + username)
        print("Invalid password entered by user {}".format(username))
    


# Handle chat after login with mutual key 2
def handle_chat(client_socket, mutual_key2):
    while True:
        encrypted_message = client_socket.recv(256).decode('utf-8')
        if encrypted_message == 'exit':
            print("Client disconnected from chat.")
            break

        # Decrypt client message
        decrypted_message = decrypt_message(mutual_key2, encrypted_message)
        print(f"Client: {decrypted_message}")
        
        # Respond to client
        response = input("You (Server): ")
        encrypted_response = encrypt_message(mutual_key2, response)
        client_socket.send(encrypted_response.encode('utf-8'))

def handle_client(client_socket, addr):
    print(f"Accepted connection from {addr}")
    log_event(f"A client has connected from {addr}")

    # Diffie-Hellman key exchange for mutual key 1
    server_secret = secrets.randbelow(P)
    server_public_key = pow(G, server_secret, P)
    
    # Send server's public key to the client
    client_socket.send(str(server_public_key).encode('utf-8'))

    # Receive client's public key
    client_public_key = int(client_socket.recv(256).decode('utf-8'))

    # Compute shared key for mutual key 1
    shared_key = pow(client_public_key, server_secret, P)

    # Generate mutual key 1
    mutual_key1 = hashlib.sha256((str(shared_key)).encode('utf-8')).digest()[:16]

    print(f"Mutual Key 1: {mutual_key1.hex()}")
    log_event(f"Mutual Key 1 created for pre-auth")

    # Start handling registration or login commands
    while True:
        encrypted_command = client_socket.recv(1024).decode('utf-8')
        command = decrypt_message(mutual_key1, encrypted_command)
        print(f"Received command: {command}")
        log_event("User has entered this command: " + command)

        # Split the command using ':' as a  delimiter
        command_parts = command.split(':')
        if len(command_parts) == 0:
            print("No command received.")
            log_event("No command received.")
            continue

        # Extract the first part of the command
        command_type = command_parts[0]

        print(command_type)

        if command_type == 'exit':
            print("Client disconnected.")
            log_event("Client has disconnected.")
            break

        elif command_type == 'register':
            log_event("Client has attempted to register.")
            handle_registration(client_socket, mutual_key1, command)

        elif command_type == 'login':
            log_event("Client has attempted to login.")
            handle_login(client_socket, mutual_key1, command)

        else:
            log_event("Unknown command received.")
            print("Unknown command received.")

    client_socket.close()

# Server setup
def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8080))
    server_socket.listen(5)
    print("Server listening on port 8080")
    log_event("Server listening on port 8080")

    while True:
        client_socket, addr = server_socket.accept()
        handle_client(client_socket, addr)

if __name__ == "__main__":
    main()
