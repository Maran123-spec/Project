import os
import hashlib
import json
import subprocess
from tkinter import filedialog, messagebox, Tk, Label, Button, Entry
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

backend = default_backend()
window = Tk()
window.title("Secure File Storage System")
window.geometry("450x300")

selected_file = ""
password_entry = None

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    return kdf.derive(password.encode())

def pad_data(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len]) * pad_len

def unpad_data(data):
    pad_len = data[-1]
    return data[:-pad_len]

def select_file():
    global selected_file
    selected_file = filedialog.askopenfilename()
    if selected_file:
        file_label.config(text=f"Selected: {os.path.basename(selected_file)}")

def secure_delete(path):
    if os.path.exists(path):
        subprocess.run(["shred", "-u", "-n", "3", path])
    else:
        messagebox.showerror("Error", "File not found for deletion.")

def encrypt_action():
    if not selected_file:
        messagebox.showerror("Error", "No file selected.")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password is required.")
        return

    with open(selected_file, 'rb') as f:
        data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    padded = pad_data(data)
    encrypted = encryptor.update(padded) + encryptor.finalize()

    enc_file = selected_file + ".enc"
    with open(enc_file, 'wb') as f:
        f.write(salt + iv + encrypted)

    sha256 = hashlib.sha256(data).hexdigest()
    metadata = {
        "original_file": os.path.basename(selected_file),
        "encrypted_file": os.path.basename(enc_file),
        "timestamp": os.popen("date").read().strip(),
        "sha256_hash": sha256
    }

    with open('metadata.json', 'a') as mf:
        mf.write(json.dumps(metadata) + '\n')

    secure_delete(selected_file)
    messagebox.showinfo("Success", f"File encrypted & saved.\nOriginal shredded.")

def decrypt_action():
    if not selected_file or not selected_file.endswith('.enc'):
        messagebox.showerror("Error", "Select a valid .enc file.")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Password is required.")
        return

    with open(selected_file, 'rb') as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    encrypted = raw[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    data = unpad_data(decrypted)

    dec_file = selected_file.replace(".enc", ".dec")
    with open(dec_file, 'wb') as f:
        f.write(data)

    current_hash = hashlib.sha256(data).hexdigest()

    # Verify hash from metadata
    valid = False
    try:
        with open("metadata.json", 'r') as f:
            for line in f:
                record = json.loads(line)
                if record['encrypted_file'] == os.path.basename(selected_file):
                    if record['sha256_hash'] == current_hash:
                        valid = True
                        break
    except:
        pass

    if valid:
        messagebox.showinfo("Success", f"File decrypted and verified.\nSaved as: {dec_file}")
    else:
        messagebox.showwarning("Warning", f"Decrypted file saved but hash mismatch!")

# === GUI Elements ===
file_label = Label(window, text="No file selected", fg="blue")
file_label.pack(pady=10)

Button(window, text="Select File", command=select_file).pack()

Label(window, text="Enter Password:").pack()
password_entry = Entry(window, show="*", width=30)
password_entry.pack(pady=5)

Button(window, text="Encrypt File", command=encrypt_action, bg="green", fg="white").pack(pady=5)
Button(window, text="Decrypt File", command=decrypt_action, bg="orange", fg="white").pack(pady=5)

Button(window, text="Exit", command=window.quit, bg="red", fg="white").pack(pady=10)

window.mainloop()
