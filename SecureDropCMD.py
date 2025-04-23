import cmd, sys, os, json, hashlib, socket, threading, time
from hmac import compare_digest

PORT = 50000
INTERVALS = 5 #seconds

class SecureDrop(cmd.Cmd):
    intro = "Welcome to SecureDrop.\nType 'help' or ? to list commands.\n"
    prompt = "SecureDrop> "
    users = {}  # Only 1 user supported, keeping plural in case that changes (Extra Credit?)
    contacts = {}
    current_email = None
    online_contacts = {}

    # ----- SecureDrop Commands -----
    # TODO: Add security for contact info (Confidentiality + Integrity)
    # -Require password to make changes to contacts?
    def do_add(self, arg):
        """Add a new contact"""
        email = input("Enter contact's email address: ")
        if email in self.contacts:
            print("Contact already exists. Updating information.")
        name = input("Enter contact's full name: ")

        self.contacts[email] = {
            "full_name": name,
            "contacts": self.contacts.get(email, {}).get("contacts", [])
        }
        if self.current_email and self.current_email not in self.contacts[email]["contacts"]:
            self.contacts[email].setdefault("conflict", []).append(self.current_email)

        self.save_contacts()
        print("Contact added successfully!")
        return False

    def do_list(self, arg):
        """List all online contacts"""
        '''
        if len(self.contacts) == 0:
            print("No contacts found.")
            return False
        '''
        if not self.online_contacts:
            print("No mutual contacts online.")
            return False

        print("\nOnline Contacts:")
        for email, info in self.contacts.items():
            print(f"- {info['full_name']} ({email})")
        return False

    def do_send(self, arg):
        """Initiate file transfer with a contact"""
        return False

    # For some reason the cmdloop just stopped exiting when this was called,
    # so I decided to take matters into my own hands and hit it the sys.exit().
    # -Keeping 'return True' because that is theoretically how this is supposed
    #   to exit.
    def do_exit(self, arg):
        """Exits the SecureDrop shell"""
        print("Exiting SecureDrop")
        self.users = {}
        self.contacts = {}
        sys.exit()
        return True

    # ----- CLI Management -----
    def preloop(self):
        """Check if user is registered. Initialize first time setup if not,
        continue with user login otherwise"""
        self.load_users()
        if len(self.users) == 0:
            self.first_time_setup()
        else:
            self.user_login()
            self.load_contacts()

    def precmd(self, line):
        return line.lower()

    # ----- Custom Methods -----
    # Do we want these methods as part of the class or as a separate module?
    # Pros: Cleaner/Smaller class definition
    # Cons: Lose easy access to class data
    def first_time_setup(self):
        """Request to register a new user, exit shell if denied."""
        if os.path.exists("users.json"):
            self.load_users()
            if len(self.users) > 0:
                print("Another instance has registered a user. Proceeding to login.")
                self.user_login()
                self.load_contacts()
                return
        # If key exists but users.json does not, users.json was likely deleted.
        # -Delete key so new one is generated during password creation.
        # -Should maybe do the same with contacts?
        # -Might want to move this somewhere else in case users.json was deleted
        #   accidentally and could be recovered.
        if os.path.exists("key"):
            os.remove("key")

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

    def load_users(self):
        """Load existing users from users.json"""
        if os.path.exists("users.json"):
            with open("users.json", "r") as file:
                self.users = json.load(file)

    def load_contacts(self):
        """Load existing contacts from contacts.json."""
        if os.path.exists("contacts.json"):
            with open("contacts.json", "r") as file:
                self.contacts = json.load(file)

    def save_users(self):
        """Save users to the JSON file."""
        with open("users.json", "w") as file:
            json.dump(self.users, file)
    
    # Currently overwrites entire contacts.json file on every call.
    # -Probably not a big deal, but theoretically inefficient for 
    #   large numbers of contacts.
    # -Could be optimized to only save changes.
    def save_contacts(self):
        """Save users to the JSON file."""
        with open("contacts.json", "w") as file:
            json.dump(self.contacts, file)

    # TODO: Security for username?
    def register_user(self):
        """user registration."""
        full_name = input("Enter Full Name: ")

        # Email acquisition loop
        # Figured it might be better to loop it instead of ending registration
        # Maybe add a way to switch to login in case they forgot they registered?
        # NOTE: This is likely unnecessary as the app only supports one 
        #       registered user at a time.
        while True:
            email = input("Enter Email Address: ")
            if email in self.users:
                print("Error: Email already registered!")
            else:
                break

        # Password acquisition loop
        # -Currently hashing after confirmation, but this does technically leave
        #   the program more vulnerable to memory dumping in specific scenarios.
        while True:
            password = input("Enter Password: ")
            confirm_password = input("Re-enter Password: ")
            if password != confirm_password:
                print("Error: Passwords do not match!")
            else:
                print("Passwords Match.")
                password = sign(password)
                break

        self.users[email] = {
            "full_name": full_name,
            "password": password
        }
        self.save_users()
        print("User registered successfully!")

    # Potentially want to add max login attempts to protect against brute force?
    def user_login(self):
        """Login user with email + password"""
        while True:
            email = input("Enter Email Address: ")
            password = input("Enter Password: ")
            password = sign(password)
            if email in self.users and compare_digest(password, self.users[email]["password"]):
                self.current_email = email
                self.online_contacts = {}

                threading.Thread(target=send_broadcast, args = (email, 5000), daemon=True).start()
                threading.Thread(target=get_broadcast, args=(email, self.contacts, self.online_contacts), daemon=True).start()
                return
            print("Email and Password Combination Invalid.\n")

# UDP Broadcast - send messages to others on network.
# Create UDP, enable broadcast, and keep boradcasting in intervals
def send_broadcast(self, email):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        message = f"Online: {email}".encode()
        while True:
            s.sendto(message, ('<broadcast>', PORT))
            time.sleep(INTERVALS)

# Listen for broadcast, updates online list with mutual contacts online.
def get_broadcast(user_email, contacts, online_contacts):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(('', PORT))
        while True:
            data, _ = s.recvfrom(1024)
            msg = data.decode()
            if msg.startswith("Online:"):
                contact_email = msg.split(":")[1].strip()
                if contact_email in contacts:
                    contact_entry = contacts[contact_email]
                    if "contacts" in contact_entry and user_email in contact_entry["contacts"]:
                        online_contacts[contact_email] = contact_entry["full_name"]

# Hash password for security.
# Currently using blake2b with a locally stored key
# idk how tf to use these crypto libraries
def sign(password):
    blake2b = hashlib.blake2b(key=get_key(), digest_size=16)
    blake2b.update(password.encode())
    return blake2b.hexdigest()

# Can't help but feel like storing the key in its own file is counterintuitive
# to security, should find a more secure solution.
# -Embed it somewhere within the hash itself?
def get_key():
    if os.path.exists("key"):
        with open("key", "rb") as file:
            key = file.read()
    else:
        with open("key", "wb") as file:
            key = os.urandom(32)
            file.write(key)
    return key

if __name__ == '__main__':
    SecureDrop().cmdloop()
