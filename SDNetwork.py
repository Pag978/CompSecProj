import socket
import threading
import time
import json

# Networking parameters – these can be secured and enhanced later.
BROADCAST_PORT = 50000
BROADCAST_INTERVAL = 3      # seconds between successive broadcast messages
OFFLINE_TIMEOUT = 6         # seconds after which a node is considered offline
BROADCAST_ADDRESS = '<broadcast>'  # UDP broadcast address

class DiscoveryService(threading.Thread):
    """
    Background service that broadcasts the local user's identity and listens for
    broadcast messages on a local network. Currently, messages are plain JSON packets.
    
    Later, you can (a) encrypt these messages, (b) add a digital signature, and (c) perform mutual
    authentication to mitigate impersonation and packet sniffing.
    """
    def __init__(self, email, name):
        threading.Thread.__init__(self)
        self.email = email
        self.name = name
        self.daemon = True
        self.online_contacts = {}       # { email: { "name": ..., "last_seen": ... } }
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # Allows testing w/ multiple terminals on the same machine
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1) # Allows testing w/ multiple terminals on the same machine
        self.sock.bind(("", BROADCAST_PORT))
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
        message = json.dumps({
            "type": "HELLO",
            "email": self.email,
            "name": self.name
            # Future: include a flag or a signature to prove reciprocal contact
        })
        try:
            self.sock.sendto(message.encode(), (BROADCAST_ADDRESS, BROADCAST_PORT))
        except Exception as e:
            print("Broadcast error:", e)
    
    def _process_message(self, data, addr):
        try:
            message = json.loads(data.decode())
            if message["type"] == "HELLO":
                sender_email = message["email"]
                sender_name = message["name"]
                # Ignore messages from ourselves
                if sender_email == self.email:
                    return
                # Update or add the contact with timestamp
                self.online_contacts[sender_email] = {
                    "name": sender_name,
                    "last_seen": time.time()
                }
        except Exception:
            # Malformed packets (or future encrypted messages not yet handled) can be ignored.
            pass
    
    def _cleanup_contacts(self):
        """Removes contacts that have not been heard from within OFFLINE_TIMEOUT."""
        cur_time = time.time()
        # Iterate over copy of dict, avoiding runtime error of changing dict size during iteration.
        for email, info in list(self.online_contacts.items()):
            if cur_time - info["last_seen"] > OFFLINE_TIMEOUT:
                del self.online_contacts[email]

    def get_online_contacts(self):
        """Return a snapshot of online contacts."""
        return self.online_contacts.copy()
    
    def stop(self):
        """Stop the broadcast listener thread."""
        self.running = False
    