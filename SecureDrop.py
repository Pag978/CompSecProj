import cmd
import json
import os
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


def main():
    users = load_users()
    if len(users) == 0:
        first_time_setup()


if __name__ == '__main__':
    main()
