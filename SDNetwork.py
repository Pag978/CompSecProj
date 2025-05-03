import os
import sys
import socket
import threading
import time
import json
import logging
import struct

from Crypto.Random import get_random_bytes
from queue import Queue, Empty

import SDSecurity

# DiscoveryService parameters
BROADCAST_PORT = 50000
BROADCAST_INTERVAL = 3             # Seconds between successive broadcast messages
OFFLINE_TIMEOUT = 6                # Seconds after which a user is considered offline
BROADCAST_ADDRESS = '<broadcast>'  # UDP broadcast address

# FileTransferService parameters
EXCHANGE_PORT = 60000
SAVE_DIR = 'received_files' # Where the file will be saved.
SESSION_TIMEOUT = 60        # Seconds of inactivity before session closes (unused atm)

CHUNK_SIZE = 4096           # Max bytes of data to process at a time
CHUNK_HEADER_SIZE = 4       # Size of the header sent with file chunks (A single unsigned int)

print_lock = threading.Lock()   # Thread lock for printing to stdout
input_requests = Queue()        # Queue to send input requests to the main thread

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
                # Still using CHUNK_SIZE here, should maybe use chunk header as implemented
                # for file transfer in case unwanted data is added to the incoming packets.
                # Not sure if this works the same for UDP though.
                data, addr = self.sock.recvfrom(CHUNK_SIZE)
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
                        "certificate": cert,
                        "ip": addr[0],
                        "last_seen": time.time()
                    }
                    logging.info(f"Discovered contact: {sender_email} from {addr[0]}")
                    contacts = SDSecurity.load_and_decrypt(self.contacts_file, self.aes_key)
                    if sender_email in contacts:
                        if self.cert.get("email") in sender_added:
                            if not contacts.get(sender_email).get("reciprocated", False):
                                contacts[sender_email]["reciprocated"] = True
                                SDSecurity.encrypt_and_store(contacts, self.contacts_file, self.aes_key)
                                logging.info(f"Reciprocation established with {sender_email}")
                        elif contacts.get(sender_email).get("reciprocated"):
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
            if cur_time - info.get("last_seen") > OFFLINE_TIMEOUT:
                self.online_contacts.pop(email)
                logging.info(f"{email} went offline.")

    def get_online_contacts(self):
        """Return a snapshot of online contacts."""
        return self.online_contacts.copy()
    
    def stop(self):
        """Stop the broadcast listener thread."""
        logging.info("Stopping DiscoveryService.")
        self.running = False

class FileTransferService(threading.Thread):
    def __init__(self, cert, peer_ip, peer_cert, filepath):
        threading.Thread.__init__(self)
        self.cert = cert
        self.peer_ip = peer_ip
        self.peer_cert = peer_cert
        self.filepath = filepath
        self.session_key = None
        self.sock = None

    def run(self):
        try:
            self._initiate_session()
            self._send_file()
        except Exception as e:
            logging.error(f"Error in file transfer session: {e}")
        finally:
            if self.sock:
                logging.info("Closing FileTransferService socket.")
                self.sock.close()
    
    def _initiate_session(self):
        """Requests to start a file transfer session & performs AES key exchange if accepted"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # -- Allow testing w/ multiple terminals on the same machine
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        
        # Connect to receiving port & request to initiate transfer
        self.sock.connect((self.peer_ip, EXCHANGE_PORT))
        request = {
            "type": "FILE_TRANSFER_REQUEST",
            "certificate": self.cert,
            "filename": os.path.basename(self.filepath)
        }
        self.sock.send(json.dumps(request).encode())
        logging.info(f"Sent request for file transfer to {self.peer_cert['email']} at {self.peer_ip}")
        response = json.loads(self.sock.recv(CHUNK_SIZE).decode())
        if response.get("type") != "FILE_TRANSFER_APPROVED":
            safe_print("File transfer request was not approved.")
            raise Exception("File transfer session not approved.")

        # Create & exchange AES session key, encrypted with receiver's RSA public key
        try:
            self.session_key = get_random_bytes(SDSecurity.AES_KEY_SIZE)
            peer_pub = self.peer_cert.get("public_key").encode()
            encrypted_key = SDSecurity.encrypt_rsa(self.session_key.hex().encode(), peer_pub)
            key_exchange = {"type": "SESSION_KEY", "key": encrypted_key.decode()}
            self.sock.send(json.dumps(key_exchange).encode())
            logging.info(f"File transfer session initiated with {self.peer_ip}!")
        except Exception as e:
            logging.error(f"Error performing key exchange: {e}")
    
    def _send_file(self):
        """Sends file in 4096-byte chunks, encrypted with AES session key"""
        try:
            filesize = os.path.getsize(self.filepath)
            data = json.dumps({"TYPE": "FILE_INFO", "size": filesize}).encode()
            # Add newline delimiter so receiver knows when info header ends
            data += b"\n"
            self.sock.send(data)
            logging.debug(f"Data sent: {data}")
            with open(self.filepath, "rb") as file:
                while chunk := file.read(CHUNK_SIZE):
                    encrypted_chunk = SDSecurity.encrypt_aes(chunk, self.session_key)
                    # Add chunk header to address issues with TCP streaming & filesize
                    # Tells receiver how much data it is expected to process in each individual chunk
                    # Header size is 4 bytes, "!I" = unsigned int packed for network use (big-endian)
                    chunk_header = struct.pack("!I", len(encrypted_chunk))
                    self.sock.sendall(chunk_header + encrypted_chunk)
            logging.info(f"{self.filepath} sent successfully!")
        except Exception as e:
            logging.error(f"Error sending file: {e}")

class FileTransferListener(threading.Thread):
    def __init__(self, private_key, cert):
        threading.Thread.__init__(self)
        self.private_key = private_key
        self.cert = cert
        self.running = True
        self.daemon = True
    
    def run(self):
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # -- Allow testing w/ multiple terminals on the same machine
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        try:
            # Listen for incoming file transfer requests
            server_sock.bind(("", EXCHANGE_PORT))
            server_sock.listen(5)
            logging.info(f"Listening for file transfer requests on port {EXCHANGE_PORT}.")
            while self.running:
                try:
                    client_sock, addr = server_sock.accept()
                    # -- Allow testing w/ multiple terminals on the same machine
                    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
                    client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    # Create handler thread for each incoming connection
                    threading.Thread(target=self.handle_transfer, args=(client_sock, addr)).start()
                except Exception as e:
                    logging.error(f"Error accepting file transfer connection: {e}")
        except Exception as e:
            logging.error(f"Error initiating FileTransferListener: {e}")
        finally:
            server_sock.close()

    def handle_transfer(self, sock, addr):
        """Handles incoming file transfer requests"""
        try:
            # Receive request for transfer & prompt user for response
            request = json.loads(sock.recv(CHUNK_SIZE).decode())
            if request.get("type") != "FILE_TRANSFER_REQUEST":
                logging.error("Invalid file transfer request received.")
                sock.close()
                return
            email = request.get("certificate").get("email")
            filename = request.get("filename", "unknown_file")
            choice = request_input(f"{email} is requesting to transfer {filename}. Accept? (y/n): ").strip().lower()
            if choice != "y":
                sock.send(json.dumps({"type": "FILE_TRANSFER_DENIED"}).encode())
                logging.info(f"Denied file transfer request from {email}.")
                sock.close()
                return
            sock.send(json.dumps({"type": "FILE_TRANSFER_APPROVED"}).encode())
            logging.info(f"Approved file transfer request from {email}.")

            # Perform AES key exchange
            key_exchange = json.loads(sock.recv(CHUNK_SIZE).decode())
            if key_exchange.get("type") != "SESSION_KEY":
                raise Exception("AES session key not received.")
            encrypted_key = key_exchange.get("key")
            decrypted_hex = SDSecurity.decrypt_rsa(encrypted_key, self.private_key.decode())
            session_key = bytes.fromhex(decrypted_hex.decode())
            logging.info("AES session key received!")

            # Receive info header by checking for newline
            info = json.loads(recv_info_header(sock).decode())
            filesize = info.get("size")
            if filesize is None:
                filesize = 0
                raise Exception("Filesize is 'None', is the file empty?")
            received = 0
            outfile = os.path.join(SAVE_DIR, filename)
            if not os.path.exists(SAVE_DIR):
                os.mkdir(SAVE_DIR)
            
            # Receive file in 4096-byte chunks
            with open(outfile, "wb") as file:
                while received < filesize:
                    chunk_header = recv_n_bytes(sock, CHUNK_HEADER_SIZE)
                    block_length = struct.unpack("!I", chunk_header)[0]
                    encrypted_chunk = recv_n_bytes(sock, block_length)
                    chunk = SDSecurity.decrypt_aes(encrypted_chunk, session_key)
                    if chunk:
                        file.write(chunk)
                        received += len(chunk)
            logging.info(f"{filename} received and saved to {outfile}!")
            safe_print(f"{filename} received and saved to '{outfile}'!")
        except Exception as e:
            logging.error(f"Error receiving file: {e}")
        finally:
            sock.close()
    
    def stop(self):
        logging.info("Stopping FileTransferListener.")
        self.running = False

# Can't use exact number like chunk header since filesize can vary
# Using newline as a delimiter instead.
def recv_info_header(sock):
    """
    Reads single bytes from socket until newline is encountered.
    Assumes a properly formatted incoming info header packet.\n
    Returns JSON header containing info about incoming file.
    """
    buffer = b""
    while True:
        data = sock.recv(1)
        if not data:
            break
        buffer += data
        if data == b"\n":
            break
    return buffer

def recv_n_bytes(sock, n):
    """Returns `n` bytes read from `sock`."""
    buffer = b""
    # Ensures all expected bytes are received properly
    while len(buffer) < n:
        data = sock.recv(n - len(buffer))
        if not data:
            raise Exception("Connection closed")
        buffer += data
    return buffer

def request_input(prompt):
    response = Queue(1)
    input_requests.put((prompt, response))
    return response.get()

# Thread safe printing so that it doesn't interfere as much with the cmd shell
def safe_print(*args, **kwargs):
    with print_lock:
        print(*args, **kwargs)
        sys.stdout.flush()
