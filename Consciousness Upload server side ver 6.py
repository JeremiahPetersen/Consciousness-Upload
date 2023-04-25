# server.py

import os
import sys
import zlib
import base64
import hashlib
import socket
import ssl
import threading
from cryptography.fernet import Fernet

BUFFER_SIZE = 4096
SERVER_ADDRESS = "0.0.0.0"
SERVER_PORT = 12345
STORAGE_PATH = "storage"

# Replace 'username' and 'password' with the actual user's credentials
USER_CREDENTIALS = {
    "username": "password",
}

def save_consciousness_data(username, data):
    user_storage_path = os.path.join(STORAGE_PATH, username)
    os.makedirs(user_storage_path, exist_ok=True)

    file_path = os.path.join(user_storage_path, "consciousness_data.bin")
    with open(file_path, 'wb') as file:
        file.write(data)
    print(f"Consciousness data for {username} saved to {file_path}")

def handle_client_connection(conn, addr):
    print(f"Connected by {addr}")

    try:
        username = conn.recv(BUFFER_SIZE).decode()
        password = USER_CREDENTIALS.get(username, None)

        if password is None:
            conn.sendall("AUTH_FAIL".encode())
            print(f"Authentication failed for {username}")
            return

        conn.sendall("AUTH_OK".encode())
        print(f"Authenticated successfully for {username}")

        data = b""
        while True:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk

        key = hashlib.sha256(password.encode()).digest()
        key = base64.urlsafe_b64encode(key)
        f = Fernet(key)
        decrypted_data = f.decrypt(data)
        decompressed_data = zlib.decompress(decrypted_data)

        save_consciousness_data(username, decompressed_data)

        print(f"Consciousness data received and saved for {username}")

    except Exception as e:
        print(f"Error during connection handling: {e}")

    finally:
        conn.close()

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((SERVER_ADDRESS, SERVER_PORT))
        sock.listen()

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="cert.pem", keyfile="key.pem")

        print(f"Server listening on {SERVER_ADDRESS}:{SERVER_PORT}")

        while True:
            conn, addr = sock.accept()
            conn = context.wrap_socket(conn, server_side=True)
            client_thread = threading.Thread(target=handle_client_connection, args=(conn, addr))
            client_thread.start()

if __name__ == "__main__":
    start_server()
    
# This code defines a server-side application for receiving consciousness data uploaded by a client. 
# The server uses SSL encryption for secure data transfer, and the data is saved in a storage directory. 
# Here's a breakdown of the code:

"""
Import necessary libraries for working with sockets, SSL, threading, encryption, compression, and file handling.

Define global variables for buffer size, server address, server port, and storage path.

Set up a dictionary of user credentials (replace 'username' and 'password' with actual user credentials).

Define helper functions:

save_consciousness_data(): Saves the received consciousness data to the specified storage path, creating a user-specific directory if it doesn't exist.
handle_client_connection(): Handles the client connection, performing authentication, receiving encrypted and compressed data, decrypting and decompressing it, 
and saving the consciousness data.
start_server(): Creates a socket, binds it to the server address and port, and listens for incoming connections. 
It wraps the connection with SSL encryption and starts a new thread to handle each client connection.
In the start_server() function:

Create a socket and set the socket options for address reuse.
Bind the socket to the server address and port.
Listen for incoming connections.
Create an SSL context for client authentication, and load the server certificate and private key.
Continuously accept incoming connections, wrapping them with SSL encryption, and start a new thread to handle each connection.
Run the start_server() function if the script is executed directly.

The server-side application listens for incoming connections from clients and handles authentication, data reception, decryption, and decompression. 
The consciousness data is then saved in a user-specific directory within the specified storage path.
"""