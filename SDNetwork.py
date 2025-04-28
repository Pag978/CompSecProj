import os
import socket
import threading
import time
import json
import logging
import base64

import SDSecurity

# Networking parameters – these can be secured and enhanced later.
BROADCAST_PORT = 50000
EXCHANGE_PORT = 60000
BROADCAST_INTERVAL = 3      # seconds between successive broadcast messages
OFFLINE_TIMEOUT = 6         # seconds after which a node is considered offline
BROADCAST_ADDRESS = '<broadcast>'  # UDP broadcast address

SERVER_HOST = 'localhost'
SERVER_PORT = 8080
SAVE_DIRECTORY = '/home/receiver/received_files' # where the file will be saved.

logging.basicConfig(
    filename="Network.log",
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s: %(message)s"
)

class DiscoveryService(threading.Thread):
    """
    Background service that broadcasts the local user's identity and listens for
    broadcast messages on a local network. Currently, messages are plain JSON packets.
    
    Later, you can (a) encrypt these messages, (b) add a digital signature, and (c) perform mutual
    authentication to mitigate impersonation and packet sniffing.
    """
    def __init__(self, certificate, contacts_file, aes_key):
        threading.Thread.__init__(self)
        self.cert = certificate
        self.contacts_file = contacts_file # Probably inefficient to constantly be reading from the file
        self.aes_key = aes_key
        self.online_contacts = {}       # { email: { "name": ..., "last_seen": ... } }
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows testing w/ multiple terminals on the same machine
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) # Allows testing w/ multiple terminals on the same machine
        try:
            self.sock.bind(("", BROADCAST_PORT))
        except Exception as e:
            logging.error(f"DiscoveryService bind error: {e}")
        self.sock.settimeout(1.0)       # Time limit on recvfrom
    
    def run(self):
        last_broadcast = 0
        while self.running:
            cur_time = time.time()
            if cur_time - last_broadcast >= BROADCAST_INTERVAL:
                self._broadcast_presence()
                last_broadcast = cur_time
            try:
                data, addr = self.sock.recvfrom(4096)
                self._process_message(data, addr)
            except socket.timeout:
                pass
            self._cleanup_contacts()
        self.sock.close()
    
    def _broadcast_presence(self):
        """
        Broadcast a JSON message announcing our presence.
        For now, the message includes our email and name.
        """
        contacts = SDSecurity.load_and_decrypt(self.contacts_file, self.aes_key)
        message = json.dumps({
            "type": "DISCOVER",
            "certificate": self.cert,
            "added": list(contacts.keys())
            # Future: include a flag or a signature to prove reciprocal contact
        })
        try:
            self.sock.sendto(message.encode(), (BROADCAST_ADDRESS, BROADCAST_PORT))
        except Exception as e:
            logging.error(f"Broadcast error: {e}")
    
    def _process_message(self, data, addr):
        """Process incoming broadcast messages"""
        try:
            message = json.loads(data.decode())
            if message.get("type") == "DISCOVER":
                cert = message.get("certificate")
                sender_added = message.get("added", [])
                if cert and SDSecurity.verify_certificate(cert):
                    sender_email = cert.get("email")
                    sender_name = cert.get("name")
                    # Ignore messages from ourselves
                    if sender_email == self.cert.get("email"):
                        return
                    # Update/add the contact with timestamp
                    self.online_contacts[sender_email] = {
                        "name": sender_name,
                        "cert": cert,
                        "ip": addr[0],
                        "last_seen": time.time()
                    }
                    logging.info(f"Discovered contact: {sender_email} from {addr[0]}")
                    contacts = SDSecurity.load_and_decrypt(self.contacts_file, self.aes_key)
                    if sender_email in contacts:
                        if self.cert.get("email") in sender_added:
                            if not contacts[sender_email].get("reciprocated", False):
                                contacts[sender_email]["reciprocated"] = True
                                SDSecurity.encrypt_and_store(contacts, self.contacts_file, self.aes_key)
                                logging.info(f"Reciprocation established with {sender_email}")
                        elif contacts[sender_email].get("reciprocated"):
                            # Update if reciprocation is lost (I feel like this constant file writing is bad)
                            contacts[sender_email]["reciprocated"] = False
                            SDSecurity.encrypt_and_store(contacts, self.contacts_file, self.aes_key)

        except Exception as e:
            # ignore invalid/unauthenticated packets
            logging.error(f"Error processing discovery message: {e}")
    
    def _cleanup_contacts(self):
        """Removes contacts that have not been heard from within OFFLINE_TIMEOUT."""
        cur_time = time.time()
        # Iterate over copy of dict, avoiding runtime error of changing dict size during iteration.
        for email, info in list(self.online_contacts.items()):
            if cur_time - info["last_seen"] > OFFLINE_TIMEOUT:
                del self.online_contacts[email]
                logging.info(f"{email} went offline.")

    def get_online_contacts(self):
        """Return a snapshot of online contacts."""
        return self.online_contacts.copy()
    
    def stop(self):
        """Stop the broadcast listener thread."""
        self.running = False

class FileTransferService(threading.Thread):
    def __init__(self):
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows testing w/ multiple terminals on the same machine
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) # Allows testing w/ multiple terminals on the same machine
        try:
            self.sock.bind((SERVER_HOST, SERVER_PORT))
        except Exception as e:
            logging.error(f"FileTransferService bind error: {e}")
        self.sock.listen(5)
        logging.info(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

    def run(self):
        while self.running:
            client_socket, client_address = self.sock.accept()
            print(f"Connection established with {client_address}")
            self.handle_file_transfer_request(client_socket, client_address)
        self.sock.close()

    def handle_file_transfer_request(self, client_socket, client_address):
        # Read full data from socket in chunks
        chunks = []
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)

        # put all chunks into one string and decode as JSON
        request = b''.join(chunks).decode()
        request_data = json.loads(request)

        # check if the request is to send a file
        if request_data['action'] == 'send_file':
            recipient_email = request_data['data']['recipient']
            file_name = request_data['data']['file_name']
            file_data = base64.b64decode(request_data['data']['file_data'])
            print(f"Contact '{recipient_email}' is sending a file: {file_name}. Accept (y/n)?")
            response = input()

            if response.lower() == 'y':
                print(f"Saving file '{file_name}'...")

                # Makes sure if directory exists
                if not os.path.exists(SAVE_DIRECTORY):
                    os.makedirs(SAVE_DIRECTORY)
                file_path = os.path.join(SAVE_DIRECTORY, file_name)
                with open(file_path, 'wb') as file:
                    file.write(file_data)

                print(f"File '{file_name}' has been successfully transferred.")
            else:
                print("File transfer has been denied.")
        client_socket.close()
    
    def stop(self):
        """Stop the file server thread."""
        self.running = False
    