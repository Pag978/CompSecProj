import cmd
import sys
import os
import datetime
import stat

from getpass import getpass

import SDSecurity

# TODO: Add integrity checks for contact info (Compare hashes from before encryption and after decryption?)
# - Main question: What would be a good solution for storing these hashes? (original data needs to be accessible)
# - Might make sense to just include contact info in user data?
# TODO: Improve security for user data/passsword
# - Add password requirements
# - Sanitize user input
# TODO: Add Certificate Authority stuff
# TODO: Improve overall file integrity
# - Example ppt mentions using timestamps?
# TODO: Figure out what the "pickle" is used for (see example ppt)

DATA_DIR = "user_data"
USER_FILE = os.path.join(DATA_DIR, "user.enc")
USER_HASH_FILE = os.path.join(DATA_DIR, "user.hash.enc")
CONTACTS_FILE = os.path.join(DATA_DIR, "contacts.enc")
SALT_FILE = os.path.join(DATA_DIR, "salt.enc")
PEPPER_FILE = os.path.join(DATA_DIR, "pepper.enc")
PICKLE_FILE = os.path.join(DATA_DIR, "pickle.enc")
LOG_FILE = os.path.join(DATA_DIR, "report.log")

SALT_SIZE = 16          # 16-byte salt used for hashing
PEPPER_SIZE = 16        # 16-byte pepper used for hashing
# PICKLE_SIZE = 16      # 16-byte pickle used for hashing
MAX_ATTEMPTS = 5        # Max login attempts before program exits

class SecureDrop(cmd.Cmd):
    intro = "Welcome to SecureDrop.\nType 'help' or ? to list commands.\n"
    prompt = "SecureDrop> "

    def __init__(self):
        super().__init__()
        self.user = None  # Only 1 user supported
        self.contacts = {}
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR, stat.S_IRWXU)

    # ----- SecureDrop Commands -----
    def do_add(self, arg):
        """Add or update a contact"""
        # Minimizing time secure data is in memory by loading contacts only when used
        self.contacts = SDSecurity.load_and_decrypt(CONTACTS_FILE, self.user["key"])
        email = input("Enter contact's email address: ")
        if email in self.contacts:
            print("Contact already exists. Updating information.")
        name = input("Enter contact's full name: ")
        
        # update/save contacts, then empty variable
        self.contacts[email] = {
            "full_name": name,
            "last_updated": datetime.datetime.now().isoformat()
        }
        SDSecurity.encrypt_and_store(self.contacts, CONTACTS_FILE, self.user["key"])
        self.contacts = {}
        print("Contact added successfully!")
        return False

    def do_list(self, arg):
        """List all online contacts"""
        self.contacts = SDSecurity.load_and_decrypt(CONTACTS_FILE, self.user["key"])
        if len(self.contacts) == 0:
            print("No contacts found.")
            return False
        print("\nOnline Contacts:")
        for email, info in self.contacts.items():
            print(f"- {info['full_name']} ({email})")
        self.contacts = {}
        return False

    def do_send(self, arg):
        """Initiate file transfer with a contact"""
        return False

    # For some reason the cmdloop stopped exiting when this was called,
    # so I decided to take matters into my own hands and hit it the sys.exit().
    # -Keeping 'return True' because that is theoretically how this is supposed to exit.
    def do_exit(self, arg):
        """Exits the SecureDrop shell"""
        self.clean_and_exit()
        return True

    # ----- CLI Management -----
    def preloop(self):
        """Check if user is registered. Initialize first time setup if not,
        continue with user login otherwise"""
        if os.path.exists(USER_FILE):
            self.user_login()
        else:
            # If user related files exist but users does not, users was likely deleted.
            # -Delete files so data isn't given to next registered user (also the new key wouldnt work).
            if os.path.exists(CONTACTS_FILE): os.remove(CONTACTS_FILE)
            if os.path.exists(USER_HASH_FILE): os.remove(USER_HASH_FILE)
            if os.path.exists(SALT_FILE): os.remove(SALT_FILE)
            if os.path.exists(PEPPER_FILE): os.remove(PEPPER_FILE)
            self.first_time_setup()

    def precmd(self, line):
        return line.lower()

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

    # Should improve input validation here
    def register_user(self):
        """user registration."""
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
                salt = SDSecurity.create_and_store_bytes(SALT_SIZE, SALT_FILE)
                pepper = SDSecurity.create_and_store_bytes(PEPPER_SIZE, PEPPER_FILE)
                key = SDSecurity.derive_key_pbkdf2(password, salt, pepper)
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
        # Don't think this is what the pickle is meant for, but idk what else to do with it
        # The example powerpoint was not very clear on how pickles are applied
        # Question: why not just use password for the hash key?
        email_hash = SDSecurity.hash_b2b(email.lower())
        email_encrypted = SDSecurity.encrypt_aes(email_hash, key)
        SDSecurity.secure_write(email_encrypted, USER_HASH_FILE)

        print("User registered successfully!")
        print("SecureDrop will now exit, restart and login to enter the SecureDrop shell.")
        return

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
                    return
                else:
                    print("Email and Password Combination Invalid.\n")
            except Exception:
                print("Email and Password Combination Invalid.\n")
            attempts += 1
        print("Login failed: Maximum attempts reached")
        # Log failed attempt and exit program
        time = datetime.datetime.now()
        with open(LOG_FILE, "a") as file:
            file.write(time.strftime("%c") + "\n")
        os.chmod(LOG_FILE, stat.S_IRUSR | stat.S_IWUSR)
        self.clean_and_exit(1)
    
    def validate_user(self, email, password):
        salt = SDSecurity.secure_read(SALT_FILE)
        pepper = SDSecurity.secure_read(PEPPER_FILE)
        key = SDSecurity.derive_key_pbkdf2(password, salt, pepper)
        ciphertext = SDSecurity.secure_read(USER_HASH_FILE)
        email_hash = SDSecurity.decrypt_aes(ciphertext, key)
        if  email_hash == SDSecurity.hash_b2b(email.lower()):
            self.user = SDSecurity.load_and_decrypt(USER_FILE, key)
            self.user["key"] = key
            return True
        else:
            return False
    
    def clean_and_exit(self, code=0):
        self.user = {}
        self.contacts = {}
        print("Exiting SecureDrop")
        sys.exit(code)

# ----- Depricated -----
# Keeping around because I think multiple salts/peppers is probably a good idea
# Will likely try implementing an improved version
#
# Check every permutation of the password with salt + pepper
# Successful decryption = correct password
# ISSUE: Leaking user data in memory if the correct password is used without the corresponding email
# SOLUTION: Make hash of the email, encrypted with the same key, and use that
# def validate_user(email, password):
#     salts = []
#     peppers = []
#     pickle_jar = []
#     with open(SALT_FILE, "rb") as file:
#         salt = file.read(SALT_SIZE)
#         while salt:
#             salts.append(salt)
#             salt = file.read(SALT_SIZE)
#     with open(PEPPER_FILE, "rb") as file:
#         pepper = file.read(PEPPER_SIZE)
#         while pepper:
#           peppers.append(pepper)
#           pepper = file.read(PEPPER_SIZE)
#     with open(PICKLE_FILE, "rb") as file:
#         pickle = file.read(PICKLE_SIZE)
#         while pickle:
#           pickle_jar.append(pickle)
#           pickle = file.read(PICKLE_SIZE)
#     with open(USER_HASH_FILE, "rb") as file:
#         ciphertext = file.read()

#     for salt in salts:
#         for pepper in peppers:
#             try:
#               key = SDSecurity.hash_b2b(password, salt, pepper)
#               email_hash = SDSecurity.decrypt_aes(ciphertext, key)
#               for pickle in pickle_jar:
#                   # Hash function running may still tell attackers that password was right w/o knowing email?
#                   if SDSecurity.hash_b2b(email, key=pickle) == email_hash:
#                     user = SDSecurity.load_and_decrypt(USER_FILE, key)
#                     # Password hash can be kept in memory after login? Theoretically requires knowing password anyway
#                     user["password"] = key
#                     return user
#             except ValueError:
#               pass
#     return {}

def main():
    app = SecureDrop()
    app.cmdloop()

if __name__ == '__main__':
    main()
