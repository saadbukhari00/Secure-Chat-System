# Secure Chat System

This project is a secure chat system that allows users to register, login, and exchange encrypted messages. The system ensures user authentication through hashed credentials and uses encryption protocols to maintain confidentiality in communication between the client and server.

## Key Features
- **User Registration:** Allows users to create accounts with a unique username and password.
- **User Login:** Authenticates users using their credentials during login.
- **Encrypted Communication:** Utilizes AES encryption for secure message exchange.
- **Credential Storage:** Stores user credentials securely by hashing passwords with SHA-256 and adding random salts.
- **Confidential Messaging:** Messages exchanged between the client and server are encrypted for privacy.

## System Architecture
The system follows a **client-server model**, where users interact with the server for registration, login, and chat sessions. The communication between the client and server is protected using encryption protocols to ensure data privacy and security.

### Registration Process
1. The client submits the username, email, and password.
2. The system uses **Diffie Hellman Key Exchange** to generate a mutual key.
3. The password is salted and hashed using the **SHA-256 algorithm**.
4. User credentials, including the hashed password and salt, are securely stored in the `creds.txt` file.
5. The server verifies the uniqueness of the username before registering the user.

### Login Process
1. After mutual key exchange using Diffie Hellman, the client encrypts the credentials using **AES-128 bit CBC mode**.
2. The server decrypts the login request and verifies the password by hashing it with the stored salt.
3. If successful, the user can access the secure chat.

### Chat System
- After successful login, the client and server exchange a new key using Diffie Hellman.
- The messages are encrypted with AES-128 and decrypted on the other end.
- Users can securely exchange messages, ensuring that the chat remains confidential.

## Credential Storage System
- **Credential File:** The `creds.txt` file stores user data including email, username, hashed password, and salt.
- **Password Hashing:** Passwords are hashed using SHA-256 combined with a random salt to protect user credentials.
- **Secure Storage:** Only the hashed passwords and salt are stored, ensuring no plain-text password is kept in the system.

## Logs Features
- **Activity Logging:** The system keeps logs of important events such as successful and failed login attempts, new user registrations, and any communication errors.
- **Security Monitoring:** Logged activities are essential for tracking suspicious behavior and potential security breaches, contributing to an improved security posture.

## Security Measures
- **Diffie Hellman Key Exchange:** Ensures secure key exchange between client and server without exposing secret keys.
- **AES Encryption:** Messages between the client and server are encrypted using AES-128 to ensure confidentiality.
- **Password Hashing with Salt:** SHA-256 with salt is used to hash passwords, providing additional security against dictionary and rainbow table attacks.
- **File Access Restrictions:** Access to `creds.txt` is restricted to the server to avoid unauthorized access.

## Testing & Evaluation
- **Functional Testing:** Verifies successful registration, login, and encrypted chat functionality.
- **Security Testing:** Tests include verifying password hashing, analyzing message encryption, and validating the security of stored credentials.
- **Network Analysis:** Tools like Wireshark can be used to confirm that all communications are encrypted.

## Demo
We can view in Wireshark the Data Transfered is Encrypted and Secure
![8](https://github.com/user-attachments/assets/c1219fd2-8f61-4814-a2f9-ac9125de504f)

We can also check that credentials are secured in creds file in sha-256 hashing with random 16-bit salt
![4](https://github.com/user-attachments/assets/1d0da74a-aaf1-4671-a175-7cd0fa756877)

We can also check the logs feature to ensure that important logs are being stored.
![9](https://github.com/user-attachments/assets/2d9a90b5-4ade-4355-9aa8-7f2696702364)




## Future Improvements
- Implement file encryption for `creds.txt` for additional protection.
- Add session timeout for increased security in case of inactivity.
- Implement security layers for detecting brute force attacks on login.

## Conclusion
This secure chat system provides robust user authentication, secure communication, and encrypted messaging. By utilizing Diffie Hellman for key exchange, AES for message encryption, and SHA-256 for password hashing, the system ensures a high level of security for user data and communication confidentiality.

