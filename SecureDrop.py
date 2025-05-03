import cmd
import sys
import os
import datetime
import stat
import logging
import traceback

from getpass import getpass
from queue import Queue, Empty

import SDSecurity
import SDNetwork

# TODO: Add Certificate Authority stuff(?)
# TODO: Figure out what the "pickle" is used for (see example ppt)
# TODO: Improve overall file integrity
# - Example ppt mentions using timestamps?

# Filepaths used in application
DATA_DIR = "user_data"
USER_FILE = os.path.join(DATA_DIR, "user.enc")
USER_HASH_FILE = os.path.join(DATA_DIR, "user.hash.enc")
CERT_FILE = os.path.join(DATA_DIR, "certificate.enc")
KEY_FILE = os.path.join(DATA_DIR, "rsa_keys.enc")
CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.enc")
SALT_FILE = os.path.join(DATA_DIR, "salt.enc")
PEPPER_FILE = os.path.join(DATA_DIR, "pepper.enc")
LOG_FILE = os.path.join(DATA_DIR, "Client.log")

SALT_SIZE = 16          # 16-byte salt used for hashing
PEPPER_SIZE = 16        # 16-byte pepper used for hashing
MAX_ATTEMPTS = 5        # Max login attempts before program exits

# Logging for the SecureDrop application
SD_log = logging.getLogger("SDApp")
SD_log.setLevel(logging.DEBUG)
SD_handler = logging.FileHandler(LOG_FILE)
SD_formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s")
SD_handler.setFormatter(SD_formatter)
SD_log.addHandler(SD_handler)

class SecureDrop(cmd.Cmd):
    intro = "Welcome to SecureDrop.\nType 'help' or ? to list commands.\n"
    prompt = "SecureDrop> "

    def __init__(self):
        super().__init__()
        self.user = None                                # Only 1 user supported
        self.rsa_keys = None                            # RSA key pair
        self.cert = None                                # Signed certificate for authentication
        self.discovery = None                           # DiscoveryService instance
        self.file_server = None                         # FileTransferListener instance
        self.input_requests = SDNetwork.input_requests  # Input requests from background services
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, stat.S_IRWXU)

    # ----- SecureDrop Commands -----
    # TODO: Sanitize user input
    def do_add(self, arg):
        """Add or update a contact"""
        try:
            # Minimizing time secure data is in memory by loading contacts only when used
            contacts = SDSecurity.load_and_decrypt(CONTACTS_FILE, self.user.get("aes_key"))
            email = input("Enter contact's email address: ").strip()
            if email in contacts:
                print("Contact already exists. Updating information.")
            name = input("Enter contact's full name: ").strip()
            contacts[email] = {
                "full_name": name,
                "reciprocated": False,
                "last_updated": datetime.datetime.now().isoformat()
            }

            SDSecurity.encrypt_and_store(contacts, CONTACTS_FILE, self.user.get("aes_key"))
            print("Contact added successfully!")
            SD_log.info(f"New contact added: {contacts.get(email)}")
        except Exception as e:
            SD_log.error(f"Error adding new contact: {e}")
            print("An error occurred while adding new contact!")
            print(f"See '{LOG_FILE}' for more details")

    def do_list(self, arg):
        """
        List users that meet the following criteria:
          1. Detected as online.
          2. Saved as a contact.
          3. Has this user saved as a contact.
        """
        try: 
            contacts = SDSecurity.load_and_decrypt(CONTACTS_FILE, self.user.get("aes_key"))
            if len(contacts) == 0:
                print("No contacts found.")
                return False
            online = {}
            if self.discovery:
                online = self.discovery.get_online_contacts()

            matched = []
            for email, info in contacts.items():
                if info.get("reciprocated", False) and email in online:
                    matched.append((email, info.get("full_name")))
            if matched:
                print("\nOnline Contacts:")
                for email, name in matched:
                    print(f"- {name} ({email})")
                print()
            else:
                print("No contacts online.")
        except Exception as e:
            SD_log.error(f"Error listing contacts: {e}")
            print("An error occurred while listing contacts!")
            print("See the logs for more details")

    def do_send(self, arg):
        """Initiate file transfer with a contact"""
        try:
            email = input("Enter recipient's email address: ")
            filepath = input("Enter the file path to send: ")
            # Check if file exists
            if not os.path.exists(filepath):
                print(f"{filepath} not found.")
                return
            
            # Check if target user is a contact
            contacts = SDSecurity.load_and_decrypt(CONTACTS_FILE, self.user.get("aes_key"))
            if email not in contacts:
                print(f"{email} not found in contacts.")
                print("Use the 'add' command to make them a contact before initiating a file transfer.")
                return
            
            # Check if contact has reciprocated
            if not contacts.get(email).get("reciprocated", False):
                print(f"{email} has not added you as a contact.")
                print("Contacts must be mutual to initiate a file transfer.")

            # Check if contact is online
            online = self.discovery.get_online_contacts()
            if email not in online:
                print(f"{email} is not online.")
                return
            
            # Begin file transfer session
            peer_ip = online.get(email).get("ip")
            peer_cert = online.get(email).get("certificate")
            choice = input(f"Initiate transfer of {filepath} to {email}? (y/n): ")
            if choice != "y":
                print("File transfer cancelled.")
                return
            session = SDNetwork.FileTransferService(self.cert, peer_ip, peer_cert, filepath)
            session.start()
        except Exception as e:
            SD_log.error(f"Error sending file (check network log): {e}")

    # For some reason the cmdloop stopped exiting when this was called,
    # so I decided to take matters into my own hands and hit it with the sys.exit().
    # -Keeping 'return True' because that is theoretically how this is supposed to exit.
    def do_exit(self, arg):
        """Exits the SecureDrop shell"""
        self.clean_and_exit()
        return True

    # ----- CLI Management -----
    def preloop(self):
        """
        Check if user is registered. Initialize first time setup if not,
        continue with user login otherwise
        """
        if os.path.exists(USER_FILE):
            self.user_login()
        else:
            # If user related files exist but users does not, users was likely deleted.
            # -Delete files so data isn't given to next registered user (also the new key wouldnt work).
            # -There's probably prettier way to do this but there's bigger issues to fix rn
            if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
            if os.path.exists(CERT_FILE): os.remove(CERT_FILE)
            if os.path.exists(CONTACTS_FILE): os.remove(CONTACTS_FILE)
            if os.path.exists(USER_HASH_FILE): os.remove(USER_HASH_FILE)
            if os.path.exists(SALT_FILE): os.remove(SALT_FILE)
            if os.path.exists(PEPPER_FILE): os.remove(PEPPER_FILE)
            self.first_time_setup()

    def precmd(self, line):
        return line.lower()
    
    # TODO: Get file transfer request interaction to occur without needing to update the cmd shell
    def postcmd(self, stop, line):
        self.process_input_requests()
        return stop

    # ----- Custom Methods -----
    def first_time_setup(self):
        """Request to register a new user, exit shell if denied."""
        print("No users are registered with this client.")
        response = input("Do you want to register a new user (y/n)?: ").lower()
        while True:
            if response.startswith("y"):
                self.register_user()
                self.clean_and_exit()
            elif response.startswith("n"):
                self.clean_and_exit()
            else:
                print("Response not recognized.")
                response = input("Please enter 'yes'(y) or 'no'(n): ")

    # TODO: Add password requirements & sanitize user input
    def register_user(self):
        """User registration."""
        try:
            full_name = input("Enter Full Name: ").strip()
            email = input("Enter Email Address: ").strip()

            # Password acquisition loop
            
            while True:
                password = getpass("Enter Password: ")
                confirm_password = getpass("Re-enter Password: ")
                if len(password) == 0:
                    print("Error: Invalid password!")
                elif password != confirm_password:
                    print("Error: Passwords do not match!")
                else:
                    print("Passwords Match!")
                    # Derived AES key from password and pseudo-random salt/pepper
                    salt = SDSecurity.create_and_store_bytes(SALT_SIZE, SALT_FILE)
                    pepper = SDSecurity.create_and_store_bytes(PEPPER_SIZE, PEPPER_FILE)
                    key = SDSecurity.derive_key_pbkdf2(password, salt, pepper)
                    SD_log.info("AES Key generated successfully!")
                    break
            
            # Password is not stored, instead it is used as the encryption key for user data
            # Login validation is performed by checking for successful decryption
            # ISSUE: How to encrypt new data (contacts) without stored key
            # Solution: Password hash can be kept in memory after login? Requires knowing password anyway
            user_data = {
                "email": email,
                "full_name": full_name,
                "created": datetime.datetime.now().isoformat()
            }
            SDSecurity.encrypt_and_store(user_data, USER_FILE, key)

            # Store email hash for login validation without leaking user data
            email_hash = SDSecurity.hash_b2b(email.lower())
            email_encrypted = SDSecurity.encrypt_aes(email_hash, key)
            SDSecurity.secure_write(email_encrypted, USER_HASH_FILE)

            # Create RSA key pair
            private_key, public_key = SDSecurity.generate_rsa_key_pair()
            SDSecurity.encrypt_and_store({"private_key": private_key.decode(), "public_key": public_key.decode()}, KEY_FILE, key)
            SD_log.info("RSA keys generated successfully!")

            # Create user certificate
            cert = SDSecurity.create_certificate(email, full_name, public_key, private_key)
            SDSecurity.encrypt_and_store(cert, CERT_FILE, key)
            SD_log.info("Certificate generated successfully!")
            SD_log.error(f"Error encrypting/storing user data: {e}")

            print("User registered successfully!")
            print("SecureDrop will now exit, restart and login to enter the SecureDrop shell.")
            SD_log.info("User registered successfully!")
            return
        except Exception as e:
            SD_log.critical(f"Registration error: {type(e).__name__} - {e}\n")
            with open("Client.log", "a") as log:
                traceback.print_exc(file=log)
            print("An error occurred during registration!")
            print(f"'{DATA_DIR}' files may have been corrupted and will be deleted on next startup.")
            print("See 'Client.log' for more details")
            if os.path.exists(USER_FILE): os.remove(USER_FILE)

    # TODO: Sanitize user input
    def user_login(self):
        """Login user with email + password"""
        attempts = 0
        while attempts < MAX_ATTEMPTS:
            email = input("Enter Email Address: ").strip()
            if email.lower() == "exit":
                self.clean_and_exit()
            password = getpass("Enter Password: ")
            try:
                if self.validate_user(email, password):
                    # Load user data & start network services after successful login
                    self.rsa_keys = SDSecurity.load_and_decrypt(KEY_FILE, self.user.get("aes_key"))
                    self.cert = SDSecurity.load_and_decrypt(CERT_FILE, self.user.get("aes_key"))
                    self.start_discovery()
                    self.start_file_server()
                    return
                else:
                    SD_log.error(f"Failed login attempt: no error (wrong email?)")
                    print("Email and Password Combination Invalid.\n")
            except Exception as e:
                SD_log.error(f"Failed login attempt: {e}")
                print("Email and Password Combination Invalid.\n")
            attempts += 1
        print("Login failed: Maximum attempts reached")
        # Log failed attempt and exit program
        SD_log.warning("Login failed - Maximum login attempts reached!")
        self.clean_and_exit(1)
    
    def validate_user(self, email, password):
        """Returns `True` given valid email & password combination, `False` otherwise."""
        # Derive key from given password
        salt = SDSecurity.secure_read(SALT_FILE)
        pepper = SDSecurity.secure_read(PEPPER_FILE)
        key = SDSecurity.derive_key_pbkdf2(password, salt, pepper)
        
        # Attempt to decrypt email hash using derived key, then compare to hash of given email
        ciphertext = SDSecurity.secure_read(USER_HASH_FILE)
        email_hash = SDSecurity.decrypt_aes(ciphertext, key)
        if  email_hash == SDSecurity.hash_b2b(email.lower()):
            # Success indicates correct password and email combination, proceed with login
            self.user = SDSecurity.load_and_decrypt(USER_FILE, key)
            self.user["aes_key"] = key
            SD_log.info(f"{email} logged in.")
            return True
        else:
            return False
    
    def start_discovery(self):
        """Starts DiscoveryService thread (broadcasts online status)"""
        try:
            self.discovery = SDNetwork.DiscoveryService(self.cert, CONTACTS_FILE, self.user.get("aes_key"))
            self.discovery.start()
            SD_log.info("Discovery service started.")
        except Exception as e:
            SD_log.error(f"Failed to start discovery service: {e}")
            print("Error starting discovery service!")
            print("Online services will not function, restarting SecureDrop is recommended.")
            print("See the logs for more details.")
    
    def start_file_server(self):
        """Starts FileTransferListener thread (Listens for file transfer requests)"""
        try:
            self.file_server = SDNetwork.FileTransferListener(self.rsa_keys.get("private_key").encode(), self.cert)
            self.file_server.start()
            SD_log.info("File transfer listener started.")
        except Exception as e:
            SD_log.error(f"Failed to start file transfer listener: {e}")
            print("Error starting file server!")
            print("You will not be able to receive file transfers, restarting SecureDrop is recommended.")
            print("See the logs for more details.")
    
    def process_input_requests(self):
        """Processes requests for input from background processes"""
        while True:
            try:
                prompt, response_queue = self.input_requests.get_nowait()
                SD_log.info("Received request for file transfer! (details in network log)")
            except Empty:
                break
            response = input(prompt)
            response_queue.put(response)

    def clean_and_exit(self, code=0):
        """Stops background processes and closes the application"""
        self.user = {}
        print("Shutting down background processes.")
        try:
            if self.discovery:
                self.discovery.stop()
                self.discovery.join(timeout=1)
            if self.file_server:
                self.file_server.stop()
                self.file_server.join(timeout=1)
        except Exception as e:
            SD_log.error(f"Error stopping background processses: {e}")
            print("An error occurred while stopping background processes!")
            print("See the logs for more details")
        finally:
            print("Exiting SecureDrop")
            SD_log.info("Exiting SecureDrop.")
            sys.exit(code)

def main():
    app = SecureDrop()
    app.cmdloop()

if __name__ == '__main__':
    main()
