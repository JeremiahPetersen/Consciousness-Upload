# client.py

import os
import sys
import time
import zlib
import base64
import hashlib
import threading
import socket
import ssl
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet

BUFFER_SIZE = 4096
COMPRESSION_LEVELS = {
    'No Compression': 0,
    'Fastest': 1,
    'Best': 9,
}

class Client:
    def __init__(self, server_address, server_port, username, password, consciousness_data, compression_level, progress_callback=None, status_callback=None):
        self.server_address = server_address
        self.server_port = server_port
        self.username = username
        self.password = password
        self.consciousness_data = consciousness_data
        self.compression_level = compression_level
        self.progress_callback = progress_callback
        self.status_callback = status_callback

    def compress(self):
        self.consciousness_data = zlib.compress(self.consciousness_data, self.compression_level)
        print("Consciousness data compressed successfully.")

    def encrypt(self):
        key = hashlib.sha256(self.password.encode()).digest()
        key = base64.urlsafe_b64encode(key)
        f = Fernet(key)
        self.consciousness_data = f.encrypt(self.consciousness_data)
        print("Consciousness data encrypted successfully.")

    def authenticate(self, sock):
        sock.sendall(self.username.encode())
        response = sock.recv(BUFFER_SIZE).decode()

        if response == "AUTH_OK":
            print("Authenticated successfully.")
            return True
        else:
            print("Authentication failed.")
            return False

    def upload(self):
        self.compress()
        self.encrypt()

        try:
            with socket.create_connection((self.server_address, self.server_port)) as sock:
                context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                sock = context.wrap_socket(sock, server_hostname=self.server_address)

                if not self.authenticate(sock):
                    messagebox.showerror("Error", "Authentication failed.")
                    return

                bytes_sent = 0
                data_length = len(self.consciousness_data)

                while bytes_sent < data_length:
                    bytes_to_send = self.consciousness_data[bytes_sent:bytes_sent + BUFFER_SIZE]
                    sent = sock.send(bytes_to_send)
                    if sent == 0:
                        raise RuntimeError("Connection to server lost")
                    bytes_sent += sent

                    if self.progress_callback:
                        progress = int((bytes_sent / data_length) * 100)
                        self.progress_callback(progress)

                print("Consciousness data uploaded successfully.")
                messagebox.showinfo("Success", "Consciousness data uploaded successfully.")
        except Exception as e:
            print(f"Error during upload: {e}")
            messagebox.showerror("Error", f"Error during upload: {e}")

def on_upload_progress(progress):
    progress_var.set(progress)
    progress_label.config(text=f"{progress}%")
    root.update_idletasks()

def on_status_change(status):
    status_label.config(text=status)
    root.update_idletasks()

def select_file():
    file_path = filedialog.askopenfilename()
    with open(file_path, 'rb') as file:
        data = file.read()
    return data

def start_upload():
    consciousness_data = select_file()

    username = username_entry.get()
    password = password_entry.get()
    compression_level = compression_var.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter your username and password.")
        return

    # Replace 'server_address' and 'server_port' with the actual address and port of your storage system
    client = Client('server_address', 12345, username, password, consciousness_data, compression_level, progress_callback=on_upload_progress, status_callback=on_status_change)

    upload_thread = threading.Thread(target=client.upload)
    upload_thread.start()

root = tk.Tk()
root.title("Consciousness Upload")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

username_label = ttk.Label(frame, text="Username:")
username_label.grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
username_entry = ttk.Entry(frame)
username_entry.grid(row=0, column=1, pady=(0, 10))

password_label = ttk.Label(frame, text="Password:")
password_label.grid(row=1, column=0, sticky=tk.W)
password_entry = ttk.Entry(frame, show="*")
password_entry.grid(row=1, column=1)

compression_label = ttk.Label(frame, text="Compression:")
compression_label.grid(row=2, column=0, sticky=tk.W, pady=(0, 10))
compression_var = tk.IntVar()
compression_var.set(0)
compression_menu = ttk.OptionMenu(frame, compression_var, *COMPRESSION_LEVELS.values())
compression_menu.grid(row=2, column=1, pady=(0, 10))

select_file_button = ttk.Button(frame, text="Select Consciousness Data File", command=start_upload)
select_file_button.grid(row=3, column=0, columnspan=2, pady=(10, 10))

progress_var = tk.IntVar()
progress_bar = ttk.Progressbar(frame, length=300, variable=progress_var, mode="determinate")
progress_bar.grid(row=4, column=0, columnspan=2)

progress_label = ttk.Label(frame, text="0%")
progress_label.grid(row=5, column=0, columnspan=2, pady=(5, 0))

status_label = ttk.Label(frame, text="")
status_label.grid(row=6, column=0, columnspan=2, pady=(5, 0))

root.columnconfigure(0, weight=1)
root.rowconfigure(0, weight=1)
frame.columnconfigure(0, weight=1)
frame.columnconfigure(1, weight=1)

root.mainloop()

# This code defines a client-side application for uploading consciousness data to a server. 
# The application features a graphical user interface (GUI) using the Tkinter library and is capable of compressing and 
# encrypting the data before sending it to the server. Here's a breakdown of the code:

"""
Import necessary libraries for creating the GUI, working with sockets, SSL, threading, encryption, compression, and file handling.

Define global variables for buffer size and compression levels.

Create a Client class that handles the connection to the server, data compression and encryption, authentication, and data upload.

Define helper functions:

on_upload_progress(): Updates the progress bar and label in the GUI.
on_status_change(): Updates the status label in the GUI.
select_file(): Opens a file dialog and reads the contents of the selected file.
start_upload(): Validates user input, creates a Client object, and starts a new thread to handle the upload process.
Create the main application window (root) and add interface elements such as labels, entries, option menus, buttons, a progress bar, and status labels using Tkinter.

Set up the grid layout and column weights for the interface elements.

Start the main Tkinter event loop to run the application.

The client-side application provides a user interface for selecting and uploading a file containing consciousness data. 
It compresses and encrypts the data before sending it to the server over a secure SSL connection. 
The GUI is updated with progress information and status messages during the upload process.

""" 