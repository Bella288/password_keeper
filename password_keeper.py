import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tkinter import *
from tkinter import messagebox, simpledialog, filedialog, ttk
import time
import random
import string
import re

# File paths
key_path = os.path.join(os.path.expanduser("~"), "Documents", "key.key")
passwords_path = os.path.join(os.path.expanduser("~"), "Documents", "passwords.json")

# Rate limiting
login_attempts = 0
lockout_time = 0

# Functions
def generate_key(master_password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    with open(key_path, "wb") as key_file:
        key_file.write(salt + key)
    return key

def load_key(master_password):
    with open(key_path, "rb") as key_file:
        salt = key_file.read(16)
        key = key_file.read()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key

def encrypt_passwords(passwords, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(json.dumps(passwords).encode())
    with open(passwords_path, "wb") as file:
        file.write(encrypted_data)

def decrypt_passwords(key):
    if not os.path.exists(passwords_path):
        return {}
    f = Fernet(key)
    with open(passwords_path, "rb") as file:
        encrypted_data = file.read()
    decrypted_data = f.decrypt(encrypted_data).decode()
    return json.loads(decrypted_data)

def set_master_password():
    master_password = simpledialog.askstring("Master Password", "Set your master password:", show='*')
    if not master_password:
        messagebox.showerror("Error", "Master password cannot be empty.")
        return
    key = generate_key(master_password)
    passwords = {}
    encrypt_passwords(passwords, key)
    messagebox.showinfo("Success", "Master password set successfully.")
    root.destroy()

def check_master_password():
    global login_attempts, lockout_time
    if lockout_time > time.time():
        time_remaining = int(lockout_time - time.time())
        messagebox.showerror("Error", f"Too many failed attempts. Please try again in {time_remaining} seconds.")
        return

    if not os.path.exists(key_path):
        set_master_password()
        return

    master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
    if not master_password:
        messagebox.showerror("Error", "Master password cannot be empty.")
        return

    try:
        key = load_key(master_password)
        decrypt_passwords(key)
        login_attempts = 0
        main_window(key)
    except Exception as e:
        login_attempts += 1
        if login_attempts >= 5:
            lockout_time = time.time() + 300  # Lock out for 5 minutes
        messagebox.showerror("Error", "Incorrect master password.")
        root.destroy()

def main_window(key):
    def add_password():
        site = simpledialog.askstring("Add Password", "Site/Service:")
        if not site:
            messagebox.showerror("Error", "Site cannot be empty.")
            return
        username = simpledialog.askstring("Add Password", "Username (if applicable):")
        email = simpledialog.askstring("Add Password", "Email used at signup:")
        if not email:
            messagebox.showerror("Error", "Email cannot be empty.")
            return
        note = simpledialog.askstring("Add Password", "Optional note:")
        if not note:
            note = "None"
        site_short_name = simpledialog.askstring("Add Password", "Site Name (e.g., YouTube for youtube.com):")
        password = simpledialog.askstring("Add Password", "Password:", show='*')
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return
        
        strength = check_password_strength(password)
        if strength != "Strong" and strength != "Very Strong":
            if not messagebox.askyesno("Password Strength", f"Password is {strength}. Are you sure you want to use this password?"):
                return

        passwords[site] = {
            "username": username,
            "email": email,
            "password": password,
            "note": note,
            "site_short": site_short_name
        }
        encrypt_passwords(passwords, key)
        messagebox.showinfo("Success", "Password added successfully.")
        update_password_list()

    def remove_password():
        site = simpledialog.askstring("Remove Password", "Site/Service to remove:")
        if site in passwords:
            del passwords[site]
            encrypt_passwords(passwords, key)
            messagebox.showinfo("Success", "Password removed successfully.")
            update_password_list()
        else:
            messagebox.showerror("Error", "Site not found.")

    def search_password():
        site = simpledialog.askstring("Search Password", "Site/Service to search:")
        if site in passwords:
            info = passwords[site]
            messagebox.showinfo("Password Found", f"Site: {site}\nUsername: {info['username']}\nEmail: {info['email']}\nPassword: {info['password']}\nNote: {info['note']}\nShort Site Name: {info['site_short']}")
        else:
            messagebox.showerror("Error", "Site not found.")

    def update_password_list():
        password_list.delete(0, END)
        for site, info in passwords.items():
            password_list.insert(END, f"Site: {site} | Username: {info['username']} | Email: {info['email']} | Note: {info['note']} | Short Site Name: {info['site_short']}")

    def on_close():
        encrypt_passwords(passwords, key)
        root.destroy()

    def rotate_key():
        current_master_password = simpledialog.askstring("Key Rotation", "Enter your current master password:", show='*')
        if not current_master_password:
            messagebox.showerror("Error", "Current master password cannot be empty.")
            return
        try:
            key = load_key(current_master_password)
            new_master_password = simpledialog.askstring("Key Rotation", "Set your new master password:", show='*')
            if not new_master_password:
                messagebox.showerror("Error", "New master password cannot be empty.")
                return
            new_key = generate_key(new_master_password)
            encrypt_passwords(passwords, new_key)
            messagebox.showinfo("Success", "Master password updated successfully.")
            root.destroy()
        except Exception as e:
            messagebox.showerror("Error", "Incorrect current master password.")

    def generate_password():
        length = simpledialog.askinteger("Password Generation", "Enter password length:", initialvalue=16, minvalue=8, maxvalue=64)
        if not length:
            messagebox.showerror("Error", "Password length cannot be empty.")
            return
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(random.choice(characters) for _ in range(length))
        strength = check_password_strength(password)
        messagebox.showinfo("Generated Password", f"Generated Password: {password}\nStrength: {strength}")
        return password

    def check_password_strength(password):
        if len(password) < 8:
            return "Very Weak"
        if not re.search(r"[a-z]", password):
            return "Weak"
        if not re.search(r"[A-Z]", password):
            return "Weak"
        if not re.search(r"[0-9]", password):
            return "Weak"
        if not re.search(r"[!@#$%^&*()_+={};:'|,.<>?/\\-]", password):
            return "Weak"
        if len(password) < 12:
            return "Moderate"
        if len(password) < 16:
            return "Strong"
        return "Very Strong"

    def backup_data():
        backup_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if backup_path:
            with open(backup_path, "w") as backup_file:
                json.dump(passwords, backup_file, indent=4)
            messagebox.showinfo("Success", f"Backup saved to {backup_path}")

    root = Tk()
    root.title("Password Keeper")

    password_list = Listbox(root, width=100, height=20)
    password_list.pack(pady=10, fill=BOTH, expand=True)

    add_button = Button(root, text="Add Password", command=add_password)
    add_button.pack(side=LEFT, padx=5)

    remove_button = Button(root, text="Remove Password", command=remove_password)
    remove_button.pack(side=LEFT, padx=5)

    search_button = Button(root, text="Search Password", command=search_password)
    search_button.pack(side=LEFT, padx=5)

    rotate_button = Button(root, text="Change Master Password", command=rotate_key)
    rotate_button.pack(side=LEFT, padx=5)

    generate_button = Button(root, text="Generate Password", command=generate_password)
    generate_button.pack(side=LEFT, padx=5)

    backup_button = Button(root, text="Backup Data", command=backup_data)
    backup_button.pack(side=LEFT, padx=5)

    root.protocol("WM_DELETE_WINDOW", on_close)

    passwords = decrypt_passwords(key)
    update_password_list()

    root.mainloop()

# Main entry point
root = Tk()
root.withdraw()  # Hide the root window

check_master_password()
