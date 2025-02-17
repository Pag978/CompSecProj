import json
import os

def load_users():
    """Load existing users from the JSON file."""
    if os.path.exists("users.json"):
        with open("users.json", "r") as file:
            return json.load(file)
    return {}

def save_users(users):
    """Save users to the JSON file."""
    with open("users.json", "w") as file:
        json.dump(users, file)

def register_user():
    """user registration."""
    users = load_users()
    
    full_name = input("Enter full name: ")
    email = input("Enter email address: ")
    
    if email in users:
        print("Error: Email already registered!")
        return
    
    password = input("Enter password: ")
    confirm_password = input("Re-enter password: ")
    
    if password != confirm_password:
        print("Error: Passwords do not match!")
        return
    
    users[email] = {
        "full_name": full_name,
        "password": password  # No security yet we can add it after
    }
    
    save_users(users)
    print("User registered successfully!")


register_user()
