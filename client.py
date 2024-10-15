import socket
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import os
import re
import getpass


# To check for strong passwords
def is_strong_password(password):
    if (len(password) < 8 or
        not re.search(r'[A-Z]', password) or
        not re.search(r'[a-z]', password) or
        not re.search(r'[0-9]', password) or
        not re.search(r'[!@#$%^&*(),.?":{}|<>]', password)):
        return False
    return True

# To check for correct mail format
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

#To check in case user and pass is same
def is_username_password_same(username, password):
    return username == password


# Diffie-Hellman parameters
P = 53  
G = 2   

# Function to compute the shared key using Diffie-Hellman
def diffie_hellman_shared_key(server_public_key):
    client_secret = secrets.randbelow(P)
    client_public = pow(G, client_secret, P)
    shared_key = pow(server_public_key, client_secret, P)
    return shared_key, client_public

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

# Function to handle user registration
def register(client_socket, mutual_key1):
    email = input("Enter email: ")

    # Validate email
    if not is_valid_email(email):
        print("Invalid email format.")
        return
    
    username = input("Enter new username: ")

    while True:
        password = getpass.getpass("Enter new password: ")
        
        # Check if username and password are the same
        if is_username_password_same(username, password):
            print("Username and password cannot be the same.")
            continue

        # Validate password strength
        if not is_strong_password(password):
            print("Password is not strong enough. Must be at least 8 characters long, with upper and lower case letters, a digit, and a special character.")
            continue

        confirm_password = getpass.getpass("Confirm your password: ")
        if password == confirm_password:
            break
        else:
            print("Passwords do not match. Please try again.")

    # Send registration details to server
    message = f"register:{email}:{username}:{password}"
    encrypted_message = encrypt_message(mutual_key1, message)
    client_socket.send(encrypted_message.encode('utf-8'))

    # Receive and decrypt the server's response
    encrypted_response = client_socket.recv(256).decode('utf-8')
    decrypted_response = decrypt_message(mutual_key1, encrypted_response)

    print(f"Server: {decrypted_response}")

    

# Function to handle user login
def login(client_socket, mutual_key1):

    username = input("Enter username: ")
    attempts = 0
    max_attempts = 3
    
    while attempts < max_attempts:
        password = getpass.getpass("Enter password: ")

        # Send login details to server
        message = f"login:{username}:{password}"
        encrypted_message = encrypt_message(mutual_key1, message)
        client_socket.send(encrypted_message.encode('utf-8'))
    
        # Receive and decrypt the server's response
        encrypted_response = client_socket.recv(256).decode('utf-8')
        decrypted_response = decrypt_message(mutual_key1, encrypted_response)

        if decrypted_response == "Login successful":
            return True, username
        
        elif decrypted_response == "Invalid username":
            print("Invalid username entered. Please try again.")
            return False, None
        
        else:
            attempts += 1
            print(f"Login failed. You have {max_attempts - attempts} attempt(s) left.")

    print("Too many failed attempts. Exiting login process.")
    return False, None
    
def display_menu():
    print("\n" + "=" * 60)
    print(" " * 10 + "WELCOME TO THE SYSTEM" + " " * 10)
    print("=" * 60)
    print(" " * 12 + "--- Menu ---" + " " * 12)
    print("=" * 60)
    print(" " * 8 + "1. Register")
    print(" " * 8 + "2. Login")
    print(" " * 8 + "3. Exit")
    print("=" * 60)
    
# Main function
def main():
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 8080))

    #share primary deffie helman calculated key for registration and before login
    # Receive server's public key
    server_public_key = int(client_socket.recv(256).decode('utf-8'))

    # Compute Diffie-Hellman shared key
    shared_key, client_public = diffie_hellman_shared_key(server_public_key)

    mutual_key1 = hashlib.sha256(str(shared_key).encode('utf-8')).digest()[:16]

    # Send client's public key to the server
    client_socket.send(str(client_public).encode('utf-8'))

    print(f"Mutual Key 1: {mutual_key1.hex()}")

    while True:
        display_menu()
        choice = input("Choose an option (1/2/3): ")
        
        if choice == '1':
            register(client_socket, mutual_key1)
        elif choice == '2':
            logged_in, username = login(client_socket, mutual_key1)
            if logged_in:
                print("Login successful. Starting chat...")
                # Receive server's public key
                server_public_key = int(client_socket.recv(256).decode('utf-8'))
                
                # Compute Diffie-Hellman shared key
                shared_key, client_public = diffie_hellman_shared_key(server_public_key)
                
                # Compute mutual key by appending username and shared key
                mutual_key2 = hashlib.sha256((username + str(shared_key)).encode('utf-8')).digest()[:16]
                
                print(f"Mutual Key 2: {mutual_key2.hex()}")
                
                # Send client's public key to the server
                client_socket.send(str(client_public).encode('utf-8'))
                
                while True:
                    # Send encrypted message to the server
                    message = input("You (Client): ")
                    if message == "exit":
                        client_socket.send(message.encode('utf-8'))
                        break
                    
                    encrypted_message = encrypt_message(mutual_key2, message)
                    client_socket.send(encrypted_message.encode('utf-8'))

                    # Receive and decrypt the server's response
                    encrypted_response = client_socket.recv(256).decode('utf-8')
                    decrypted_response = decrypt_message(mutual_key2, encrypted_response)
                    print(f"Server: {decrypted_response}")
            else:
                print("Login failed. Please try again.")
        elif choice == '3':
            print("Exiting...")
            msg = "exit"
            enc_msg = encrypt_message(mutual_key1, msg)
            client_socket.send(enc_msg.encode('utf-8'))
            break
        else:
            print("Invalid choice, please try again.")

    client_socket.close()

if __name__ == "__main__":
    main()
