# Welcome to password_keeper
A Simple Python Program for saving, storing, and managing passwords securely with 2-level encryption.

# About 2-level Encryption
- By requiring the user to set a master password when they run the program for the first time, a layer of security is added. This password is saved in a file and encrypted. The user can also change the master password at any time, as long as they can provide the current one first.
- By encrypting the file on which the passwords are contained, the second layer of encryption is added.
- Rest assured, the program is using a safe encryption method, incrementing itself thousands of times to protect against brute-force decryption.
- Using two-level encryption, the program can keep user passwords safe.
# Notes
- Remember to write down your master password, as you will be unable to use the program otherwise.
- Keep a backup of your JSON file. You can place it anywhere in your system. To do this, you can press "Backup Data" in the program and choose where to save it.
- You should also change your master password frequently to protect your data.
# Features
- Simple User Interface (UI) using Tkinter - For a simple program almost anybody can use.
- 2-layer Encryption - Using a master password and encrypted files.
- Data Backup - To keep your passwords safe in case of data loss.
- Password Generation - To generate a random password you can use.
- Password Strength Tester - To ensure you have a strong password.
