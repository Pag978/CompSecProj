import cmd, sys, os, json, datetime, random
from getpass import getpass
from hashlib import blake2b
from hmac import compare_digest
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# TODO: Add integrity checks for contact info (Compare hashes from before encryption and after decryption?)
# - Main question: What would be a good solution for storing these hashes? (original data needs to be accessible)
# - Might make sense to just include contact info in user data?

# TODO: Accept that the application only supports a single user at a time and refactor code accordingly
# - Simplify user json object and remove code that iterates through users

# TODO: Improve security for user data/passsword
# - Attempting "Salt, Pepper, and Pickle" from the example
# - Add password requirements

SALT_SIZE = 16
PEPPER_SIZE = 16
PICKLE_SIZE = 16
KEY_SIZE = 32
NONCE_SIZE = 16
TAG_SIZE = 16
USER_FILE = "user.enc"
USER_HASH_FILE = "user.hash.enc"
CONTACTS_FILE = "contacts.enc"
KEY_FILE = "key.enc"
SALT_FILE = "salt.enc"
PEPPER_FILE = "pepper.enc"
PICKLE_FILE = "pickle.enc"
LOG_FILE = "report.log"

class SecureDrop(cmd.Cmd):
    intro = "Welcome to SecureDrop.\nType 'help' or ? to list commands.\n"
    prompt = "SecureDrop> "
    user = {}  # Only 1 user supported, keeping plural in case that changes (Extra Credit?)
    contacts = {}

    # ----- SecureDrop Commands -----
    def do_add(self, arg):
        """Add a new contact"""
        email = input("Enter contact's email address: ")
        if email in self.contacts:
            print("Contact already exists. Updating information.")
        name = input("Enter contact's full name: ")
        self.contacts[email] = {"full_name": name}
        encrypt_and_store(self.contacts, CONTACTS_FILE, get_key())
        print("Contact added successfully!")
        return False

    def do_list(self, arg):
        """List all online contacts"""
        if len(self.contacts) == 0:
            print("No contacts found.")
            return False
        print("\nOnline Contacts:")
        for email, info in self.contacts.items():
            print(f"- {info['full_name']} ({email})")
        return False

    def do_send(self, arg):
        """Initiate file transfer with a contact"""
        return False

    # For some reason the cmdloop stopped exiting when this was called,
    # so I decided to take matters into my own hands and hit it the sys.exit().
    # -Keeping 'return True' because that is theoretically how this is supposed to exit.
    def do_exit(self, arg):
        """Exits the SecureDrop shell"""
        self.user = {}
        self.contacts = {}
        print("Exiting SecureDrop")
        sys.exit()
        return True

    # ----- CLI Management -----
    def preloop(self):
        """Check if user is registered. Initialize first time setup if not,
        continue with user login otherwise"""
        if os.path.exists(USER_FILE):
            self.user_login()
            self.contacts = load_and_decrypt(CONTACTS_FILE, get_key())
        else:
            self.first_time_setup()

    def precmd(self, line):
        return line.lower()

    # ----- Custom Methods -----
    def first_time_setup(self):
        """Request to register a new user, exit shell if denied."""
        # If key/contact exists but users does not, users was likely deleted.
        # -Delete key so new one is generated during user registration.
        # -Delete contacts so data isn't given to next registered user (also the new key wouldnt work).
        if os.path.exists(KEY_FILE): os.remove(KEY_FILE)
        if os.path.exists(CONTACTS_FILE): os.remove(CONTACTS_FILE)
        if os.path.exists(USER_HASH_FILE): os.remove(USER_HASH_FILE)
        if os.path.exists(SALT_FILE): os.remove(SALT_FILE)

        print("No users are registered with this client.")
        response = input("Do you want to register a new user (y/n)?: ").lower()
        while True:
            if response.startswith("y"):
                self.register_user()
                self.onecmd("exit")
            elif response.startswith("n"):
                self.onecmd("exit")
            else:
                print("Response not recognized.")
                response = input("Please enter 'yes'(y) or 'no'(n): ")

    def register_user(self):
        """user registration."""
        full_name = input("Enter Full Name: ")
        email = input("Enter Email Address: ")

        # Password acquisition loop
        while True:
            password = getpass("Enter Password: ")
            confirm_password = getpass("Re-enter Password: ")
            if password == confirm_password:
                print("Passwords Match.")
                password = hash_b2b(password, generate_salt(), get_rand_pepper())
                break
            else:
                print("Error: Passwords do not match!")

        self.user[email] = {
            "full_name": full_name
        }
        encrypt_and_store(self.user, USER_FILE, password)
        
        # Store email hash for login validation without leaking user data
        email_hash = hash_b2b(email, key=get_rand_pickle())
        with open(USER_HASH_FILE, "wb") as file:
            file.write(encrypt_aes(email_hash, password))

        print("User registered successfully!")
        print("SecureDrop will now exit, restart and login to enter the SecureDrop shell.")
        return

    def user_login(self):
        """Login user with email + password"""
        attempts = 0
        while attempts < 5:
            email = input("Enter Email Address: ")
            if email == "exit": break
            password = getpass("Enter Password: ")
            self.user = validate_user(email, password)
            if self.user:
                return
            print("Email and Password Combination Invalid.\n")
            attempts += 1
        # Not using "do_exit" here as the return value could potentially be modified to bypass login
        self.user = {}
        if attempts >= 5:
          print("Login failed: Maximum attempts reached")
          time = datetime.datetime.now()
          with open(LOG_FILE, "a") as file:
              file.write(time.strftime("%c") + "\n")
        print("Exiting SecureDrop")
        sys.exit()

# ----- Hashing -----
def generate_salt():
    salt = get_random_bytes(SALT_SIZE)
    with open(SALT_FILE, "ab") as file:
        file.write(salt)
    return salt

def get_rand_pepper():
    peppers = []
    with open(PEPPER_FILE, "rb") as file:
        pepper = file.read(PEPPER_SIZE)
        while pepper:
          peppers.append(pepper)
          pepper = file.read(PEPPER_SIZE)
    return random.choice(peppers)

def get_rand_pickle():
    pickle_jar = []
    with open(PICKLE_FILE, "rb") as file:
        pickle = file.read(PICKLE_SIZE)
        while pickle:
          pickle_jar.append(pickle)
          pickle = file.read(PICKLE_SIZE)
    return random.choice(pickle_jar)

def hash_b2b(data, salt=b"", pepper=b"", key=b""):
    """Returns blake2b hash of `data`"""
    data = data.encode() + pepper
    b2b = blake2b(digest_size=32, key=key, salt=salt)
    b2b.update(data)
    return b2b.digest()

# Check every permutation of the password with salt + pepper
# Successful decryption = correct password
# ISSUE: Leaking user data in memory if the correct password is used without the corresponding email
# SOLUTION: Make a hash of the email, encrypted with the same key, and use that
def validate_user(email, password):
    salts = []
    peppers = []
    pickle_jar = []
    with open(SALT_FILE, "rb") as file:
        salt = file.read(SALT_SIZE)
        while salt:
            salts.append(salt)
            salt = file.read(SALT_SIZE)
    with open(PEPPER_FILE, "rb") as file:
        pepper = file.read(PEPPER_SIZE)
        while pepper:
          peppers.append(pepper)
          pepper = file.read(PEPPER_SIZE)
    with open(PICKLE_FILE, "rb") as file:
        pickle = file.read(PICKLE_SIZE)
        while pickle:
          pickle_jar.append(pickle)
          pickle = file.read(PICKLE_SIZE)
    with open(USER_HASH_FILE, "rb") as file:
        ciphertext = file.read()
    
    for salt in salts:
        for pepper in peppers:
            try:
              password = hash_b2b(password, salt, pepper)
              email_hash = decrypt_aes(ciphertext, password)
              for pickle in pickle_jar:
                  if hash_b2b(email, key=pickle) == email_hash:
                    return load_and_decrypt(USER_FILE, password)
            except ValueError:
              pass
    return {}

# ----- Encryption -----
# Can't help but feel like storing the key in its own file is counterintuitive
# -Embed it somewhere? Feel like that wouldn't help much.
# -Should probably use unique keys for individual files & hashing, instead of one for everything
def get_key():
    """Returns key stored in file, or generates one if it doesn't exist"""
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as file:
            key = file.read()
    else:
        with open(KEY_FILE, "wb") as file:
            key = get_random_bytes(KEY_SIZE)
            file.write(key)
    return key
# AES-encryption: first 16-bytes are the nonce and last 16 bytes are the tag
def encrypt_aes(data, key):
    """Returns AES encrypted `data` as bytes"""
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    ciphertext = cipher.nonce + ciphertext + tag
    return ciphertext

def decrypt_aes(data, key):
    """Returns AES decrypted `data` as bytes"""
    cipher = AES.new(key, AES.MODE_GCM, nonce=data[:NONCE_SIZE])
    return cipher.decrypt_and_verify(data[NONCE_SIZE:-TAG_SIZE], data[-TAG_SIZE:])

# ----- JSON I/O -----
# Can't serialize bytes to json, so encrypting entire object for storage
# Downside: Data not encrypted while in memory
def load_and_decrypt(source, key):
    """Returns decrypted JSON object stored in `source`, if it exists."""
    if os.path.exists(source):
        with open(source, "rb") as file:
            decrypted = decrypt_aes(file.read(), key)
            return json.loads(decrypted)
    return {}

def encrypt_and_store(obj, dest, key):
    """Serializes & Encrypts JSON-compatible `obj` then writes it to `dest`."""
    encrypted = encrypt_aes(json.dumps(obj).encode(), key)
    with open(dest, "wb") as file:
        file.write(encrypted)

if __name__ == '__main__':
    SecureDrop().cmdloop()
