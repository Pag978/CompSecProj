import cmd, sys, os, json, hashlib
from hmac import compare_digest

class SecureDrop(cmd.Cmd):
  intro = "Welcome to SecureDrop.\nType 'help' or ? to list commands.\n"
  prompt = "SecureDrop> "
  file = None
  users = {}

  #----- SecureDrop Commands -----
  def do_add(self, arg):
    """Add a new contact"""
    pass

  def do_list(self, arg):
    """List all online contacts"""
    pass

  def do_send(self, arg):
    """Initiate file transfer with a contact."""
    pass
  
  # For some reason the cmdloop just stopped exiting when this was called,
  # so I decided to take matters into my own hands and hit it the the sys.exit().
  # Keeping 'return True' because that is theoretically how this is supposed to exit.
  def do_exit(self, arg):
    """Exits the SecureDrop shell"""
    print("Exiting SecureDrop")
    self.close()
    sys.exit()  
    return True 
  
  #----- CLI Management ----
  def preloop(self):
    """Check if user is registered. Initialize first time setup if not,
    continue with user login otherwise"""
    self.users = self.load_users()
    if len(self.users) == 0:
      self.first_time_setup()
    else:
      self.user_login()
  
  def precmd(self, line):
    return line.lower()
  
  #----- Custom Methods -----
  def close(self):
    if self.file:
      self.file.close()
      self.file = None
    self.users = {}
  
  # Do we want these methods as part of the class or as a separate module?
  # Pros: Cleaner/Smaller class definition
  # Cons: Lose easy access to class data
  def first_time_setup(self):
    """Request to register a new user, exit shell if denied."""
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
    """Load existing users from the JSON file."""
    if os.path.exists("users.json"):
      self.file = open("users.json", "r")
      return json.load(self.file)
    return {}
  
  def save_users(self):
    """Save users to the JSON file."""
    self.file = open("users.json", "w")
    json.dump(self.users, self.file)
  
  def register_user(self):
    """user registration."""
    full_name = input("Enter Full Name: ")

    # Email acquisition loop
    # Figured it might be better to loop it instead of ending registration
    # Maybe add a way to switch to login in case they forgot they registered?
    while True:
      email = input("Enter Email Address: ")
      if email in self.users:
        print("Error: Email already registered!")
      else:
        break
    
    # Password acquisition loop
    # Currently hashing after confirmation, but this does technically leave the
    # program more vulnerable to memory dumping
    while True:
      password = input("Enter Password: ")
      confirm_password = input("Re-enter Password: ")
      if password != confirm_password:
        print("Error: Passwords do not match!")
      else:
        break
    
    print("Passwords Match.")
    password = sign(password)
    self.users[email] = {
        "full_name": full_name,
        "password": password
    }
    
    self.save_users()
    print("User registered successfully!")
  
  def user_login(self):
    """Login user with email + password"""
    while True:
      email = input("Enter Email Address: ")
      password = input("Enter Password: ")
      password = sign(password)
      if email in self.users and compare_digest(password, self.users[email]["password"]):
        return
      print("Email and Password Combination Invalid.\n")
  
# Hash password for security.
# Currently using blake2b with a locally stored key
# idk how tf to use these crypto libraries
def sign(password):
  key = get_key()
  blake2b = hashlib.blake2b(key=key, digest_size=16)
  blake2b.update(password.encode())
  return blake2b.hexdigest()

def get_key():
  if os.path.exists("key"):
    file = open("key", "rb")
    key = file.read()
  else:
    key = os.urandom(32)
    file = open("key", "wb")
    file.write(key)
  file.close()
  return key

if __name__ == '__main__':
  SecureDrop().cmdloop()
