from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from ttkthemes import ThemedTk
from tkinter.scrolledtext import ScrolledText

# Function to derive a key from a password
def derive_key(password, salt, iterations=100000):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a file
def encrypt_file(file_path, key, salt, algorithm="AES"):
    iv = os.urandom(16)  # Generate a random IV
    if algorithm == "AES":
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    elif algorithm == "ChaCha20":
        cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the file and encrypt its contents
    with open(file_path, 'rb') as file:
        data = file.read()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

    # Write the IV, salt, and encrypted data to a new file
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as file:
        file.write(iv)
        file.write(salt)
        file.write(encrypted_data)

    return encrypted_file_path

# Function to decrypt a file
def decrypt_file(file_path, password, algorithm="AES"):
    try:
        # Read the IV, salt, and encrypted data from the file
        with open(file_path, 'rb') as file:
            iv = file.read(16)  # Read the first 16 bytes for IV
            salt = file.read(16)  # Read the next 16 bytes for salt
            encrypted_data = file.read()  # Read the rest for encrypted data

        # Derive the key using the salt
        key = derive_key(password, salt)

        # Create a cipher object using the key and IV
        if algorithm == "AES":
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        elif algorithm == "ChaCha20":
            cipher = Cipher(algorithms.ChaCha20(key, iv), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        # Write the decrypted data to a new file
        decrypted_file_path = file_path[:-4] if file_path.endswith('.enc') else file_path + '.dec'
        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)

        return decrypted_file_path
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

# Function to check password strength
def check_password_strength(password):
    strength = 0
    if len(password) >= 8:
        strength += 1
    if any(char.isdigit() for char in password):
        strength += 1
    if any(char.isupper() for char in password):
        strength += 1
    if any(char.islower() for char in password):
        strength += 1
    if any(char in "!@#$%^&*()" for char in password):
        strength += 1
    return strength

# Function to update the progress bar
def update_progress(value):
    progress['value'] = value
    root.update_idletasks()

# Function to encrypt with progress
def encrypt_with_progress():
    file_path = file_path_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file!")
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password cannot be empty!")
        return

    strength = check_password_strength(password)
    if strength < 3:
        messagebox.showwarning("Weak Password", "Your password is weak. Consider using a stronger password.")

    salt = os.urandom(16)
    key = derive_key(password, salt)
    algorithm = algorithm_var.get()

    try:
        encrypted_file_path = encrypt_file(file_path, key, salt, algorithm)
        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

    update_progress(100)

# Function to decrypt with progress
def decrypt_with_progress():
    file_path = file_path_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file!")
        return

    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password cannot be empty!")
        return

    algorithm = algorithm_var.get()

    try:
        decrypted_file_path = decrypt_file(file_path, password, algorithm)
        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {decrypted_file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {e}")

    update_progress(100)

# Function to preview the file
def preview_file():
    file_path = file_path_entry.get()
    if not file_path:
        messagebox.showerror("Error", "Please select a file!")
        return

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            content = file.read(500)  # Read the first 500 characters
            preview_window = tk.Toplevel(root)
            preview_window.title("File Preview")
            preview_text = ScrolledText(preview_window, wrap=tk.WORD, width=80, height=20)
            preview_text.insert(tk.INSERT, content)
            preview_text.pack()
    except Exception as e:
        messagebox.showerror("Error", f"Cannot preview file: {e}")

# Function to clear the UI
def clear_ui():
    file_path_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    progress['value'] = 0

# Create the main window
root = ThemedTk(theme="arc")  # Use a modern theme
root.title("Advanced Encryption Tool")
root.geometry("600x400")

# Create and place widgets
main_frame = ttk.Frame(root, padding="10")
main_frame.pack(fill=tk.BOTH, expand=True)

# File selection
file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding="10")
file_frame.pack(fill=tk.X, pady=5)

file_path_entry = ttk.Entry(file_frame, width=50)
file_path_entry.pack(side=tk.LEFT, padx=5)

file_button = ttk.Button(file_frame, text="Browse", command=lambda: file_path_entry.insert(0, filedialog.askopenfilename()))
file_button.pack(side=tk.LEFT, padx=5)

preview_button = ttk.Button(file_frame, text="Preview", command=preview_file)
preview_button.pack(side=tk.LEFT, padx=5)

# Password entry
password_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
password_frame.pack(fill=tk.X, pady=5)

password_entry = ttk.Entry(password_frame, show="*", width=50)
password_entry.pack(side=tk.LEFT, padx=5)

# Algorithm selection
algorithm_frame = ttk.LabelFrame(main_frame, text="Encryption Algorithm", padding="10")
algorithm_frame.pack(fill=tk.X, pady=5)

algorithm_var = tk.StringVar(value="AES")
aes_radio = ttk.Radiobutton(algorithm_frame, text="AES", variable=algorithm_var, value="AES")
aes_radio.pack(side=tk.LEFT, padx=5)

chacha_radio = ttk.Radiobutton(algorithm_frame, text="ChaCha20", variable=algorithm_var, value="ChaCha20")
chacha_radio.pack(side=tk.LEFT, padx=5)

# Progress bar
progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
progress_frame.pack(fill=tk.X, pady=5)

progress = ttk.Progressbar(progress_frame, orient='horizontal', length=500, mode='determinate')
progress.pack()

# Buttons
button_frame = ttk.Frame(main_frame, padding="10")
button_frame.pack(fill=tk.X, pady=5)

encrypt_button = ttk.Button(button_frame, text="Encrypt File", command=encrypt_with_progress)
encrypt_button.pack(side=tk.LEFT, padx=5)

decrypt_button = ttk.Button(button_frame, text="Decrypt File", command=decrypt_with_progress)
decrypt_button.pack(side=tk.LEFT, padx=5)

clear_button = ttk.Button(button_frame, text="Clear", command=clear_ui)
clear_button.pack(side=tk.LEFT, padx=5)

# Run the application
root.mainloop()