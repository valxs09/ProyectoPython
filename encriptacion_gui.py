import tkinter as tk
from tkinter import messagebox
import bcrypt
import base64
from cryptography.fernet import Fernet
import os

def generate_salt():
    return bcrypt.gensalt()

def hash_password(password, salt):
    return bcrypt.hashpw(password.encode(), salt)

def verify_password(password, stored_hash):
    return bcrypt.checkpw(password.encode(), stored_hash)

def generate_key():
    return Fernet.generate_key()

def encrypt_message():
    message = message_entry.get()
    password = password_entry.get()
    if not message or not password:
        messagebox.showerror("Error", "Por favor, ingresa un mensaje y una clave secreta.")
        return
    
    salt = generate_salt()
    hashed_password = hash_password(password, salt)
    key = generate_key()
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    

    encrypted_key = base64.b64encode(bcrypt.hashpw(key, salt))
    
    with open("mensaje_encriptado.txt", "wb") as file:
        file.write(encrypted_message)
    with open("clave_secreta.txt", "wb") as file:
        file.write(encrypted_key)
    with open("hash_contraseña.txt", "wb") as file:
        file.write(hashed_password)
    with open("salt.txt", "wb") as file:
        file.write(salt)
    
    messagebox.showinfo("Éxito", "Mensaje encriptado y guardado.")
    
    message_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

def decrypt_message():
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Por favor, ingresa la clave secreta para desencriptar.")
        return
    
    try:
        with open("clave_secreta.txt", "rb") as file:
            encrypted_key = file.read()
        with open("mensaje_encriptado.txt", "rb") as file:
            encrypted_message = file.read()
        with open("hash_contraseña.txt", "rb") as file:
            stored_hash = file.read()
        with open("salt.txt", "rb") as file:
            salt = file.read()
        
        if not verify_password(password, stored_hash):
            messagebox.showerror("Error", "Contraseña incorrecta.")
            return
        
        key = bcrypt.hashpw(encrypted_key, salt)
        key = base64.b64decode(key)
        fernet = Fernet(key)
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        messagebox.showinfo("Mensaje Desencriptado", decrypted_message)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo desencriptar el mensaje: {e}")

app = tk.Tk()
app.title("Cifrado y Descifrado de Mensajes")
app.geometry("400x300")

tk.Label(app, text="Mensaje:").pack()
message_entry = tk.Entry(app, width=40)
message_entry.pack()

tk.Label(app, text="Clave Secreta:").pack()
password_entry = tk.Entry(app, width=40, show="*")
password_entry.pack()

tk.Button(app, text="Encriptar", command=encrypt_message).pack()
tk.Button(app, text="Desencriptar", command=decrypt_message).pack()

app.mainloop()
