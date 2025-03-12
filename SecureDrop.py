import json
import os
import sys


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
    print("Passwords Match.")

    users[email] = {
        "full_name": full_name,
        "password": password  # No security yet we can add it after
    }

    save_users(users)
    print("User registered successfully!")


def first_time_setup():
    print("No users are registered with this client.")
    response = input("Do you want to register a new user (y/n)?: ").lower()
    while True:
        if response.startswith("y"):
            register_user()
            print("Exiting SecureDrop")
            sys.exit()
        elif response.startswith("n"):
            print("Exiting SecureDrop")
            sys.exit()
        else:
            print("Response not recognized.")
            response = input("Please enter 'yes'(y) or 'no'(n): ")


def main():
    users = load_users()
    if len(users) == 0:
        first_time_setup()


if __name__ == '__main__':
    main()
