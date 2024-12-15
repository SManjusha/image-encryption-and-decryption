import numpy as np
from PIL import Image
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from tkinter import Tk, Label, Button, Entry, filedialog, messagebox, Frame

# Encryption and Decryption Functions
def generate_initial_vector(tent_map_length=128):
    X0 = np.random.rand()
    IV = []
    for _ in range(tent_map_length // 8):
        X0 = 2 * X0 if X0 < 0.5 else 2 * (1 - X0)
        IV.append(int(X0 * 255))
    return bytes(IV)

def pad_image(image_data):
    h, w, c = image_data.shape
    new_h = h if h % 16 == 0 else (h // 16 + 1) * 16
    new_w = w if w % 16 == 0 else (w // 16 + 1) * 16
    padded_image = np.zeros((new_h, new_w, c), dtype=np.uint8)
    padded_image[:h, :w, :] = image_data
    return padded_image, (h, w, c)

def encrypt_image(image_path, key):
    image = Image.open(image_path).convert('RGB')
    image_data = np.array(image)
    padded_image, original_shape = pad_image(image_data)
    iv = generate_initial_vector()
    key_hash = hashlib.sha256(key.encode()).digest()[:16]
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    image_data_bytes = padded_image.tobytes()
    padded_image_data = pad(image_data_bytes, AES.block_size)
    encrypted_image_data = cipher.encrypt(padded_image_data)

    encrypted_image_array = np.frombuffer(encrypted_image_data[:padded_image.size], dtype=np.uint8)
    encrypted_image_array = encrypted_image_array.reshape(padded_image.shape)
    
    return encrypted_image_array, encrypted_image_data, iv, padded_image.shape, original_shape

def decrypt_image(encrypted_image_data, iv, key, padded_shape, original_shape):
    key_hash = hashlib.sha256(key.encode()).digest()[:16]
    cipher = AES.new(key_hash, AES.MODE_CBC, iv)
    decrypted_image_data = cipher.decrypt(encrypted_image_data)
    unpadded_image_data = unpad(decrypted_image_data, AES.block_size)
    decrypted_image_array = np.frombuffer(unpadded_image_data, dtype=np.uint8)
    decrypted_image = np.reshape(decrypted_image_array, padded_shape)
    h, w, c = original_shape
    return decrypted_image[:h, :w, :]

# GUI Functions
def choose_file():
    file_path = filedialog.askopenfilename(title="Select Image File")
    if file_path:
        label_file.config(text=f"Selected File: {file_path}")
        global image_file_path
        image_file_path = file_path

def enter_key_encrypt():
    global encryption_key
    encryption_key = key_entry_encrypt.get()
    if encryption_key:
        messagebox.showinfo("Success", "Encryption key set successfully!")
    else:
        encryption_key = None
        messagebox.showerror("Error", "Please enter a valid encryption key!")

def enter_key_decrypt():
    global decryption_key
    decryption_key = key_entry_decrypt.get()
    if decryption_key:
        messagebox.showinfo("Success", "Decryption key set successfully!")
    else:
        decryption_key = None
        messagebox.showerror("Error", "Please enter a valid decryption key!")

def encrypt_file():
    if not image_file_path:
        messagebox.showerror("Error", "No file selected!")
        return
    if not encryption_key:
        messagebox.showerror("Error", "Encryption key is not set! Please enter a key and press 'Enter Key'.")
        return
    try:
        encrypted_image_array, encrypted_image_data, iv, padded_shape, original_shape = encrypt_image(image_file_path, encryption_key)
        
        # Save the encrypted image for visualization
        encrypted_image = Image.fromarray(encrypted_image_array, 'RGB')
        encrypted_image.save("encrypt.jpeg")

        # Save the true encrypted data
        with open("encrypt.bin", "wb") as encrypted_file:
            encrypted_file.write(encrypted_image_data)

        # Save the metadata
        with open("meta.txt", "w") as metadata_file:
            metadata_file.write(f"{iv.hex()}\n")
            metadata_file.write(f"{padded_shape}\n")
            metadata_file.write(f"{original_shape}\n")
            metadata_file.write(hashlib.sha256(encryption_key.encode()).hexdigest())  # Save hash of encryption key

        messagebox.showinfo("Success", "Files saved: 'encrypt.jpeg', 'encrypt.bin', and 'meta.txt'.")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

def decrypt_file():
    if not decryption_key:
        messagebox.showerror("Error", "Decryption key is not set! Please enter a key and press 'Enter Key'.")
        return
    try:
        with open("meta.txt", "r") as metadata_file:
            iv_hex = metadata_file.readline().strip()
            padded_shape = eval(metadata_file.readline().strip())
            original_shape = eval(metadata_file.readline().strip())
            stored_key_hash = metadata_file.readline().strip()

        # Verify if the entered key matches the stored key hash
        entered_key_hash = hashlib.sha256(decryption_key.encode()).hexdigest()
        if entered_key_hash != stored_key_hash:
            messagebox.showerror("Error", "Key does not match! Decryption cannot proceed.")
            return

        iv = bytes.fromhex(iv_hex)
        with open("encrypt.bin", "rb") as encrypted_file:
            encrypted_image_data = encrypted_file.read()
        
        decrypted_image = decrypt_image(encrypted_image_data, iv, decryption_key, padded_shape, original_shape)
        decrypted_image_pil = Image.fromarray(decrypted_image, 'RGB')
        decrypted_image_pil.save("decrypt.jpeg")
        messagebox.showinfo("Success", "Decrypted image saved as 'decrypt.jpeg'.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# GUI Setup
root = Tk()
root.title("Image Encryption and Decryption")
root.geometry("400x450")
root.configure(bg="#f5f5f5")

# Header
Label(root, text="IMAGE ENCRYPTION AND DECRYPTION", font=("Arial", 16, "bold"), bg="#f5f5f5").pack(pady=15)

# File Selection Frame
file_frame = Frame(root, bg="#f5f5f5")
file_frame.pack(pady=10, fill="x", padx=10)
Button(file_frame, text="Choose File", command=choose_file, width=20, bg="#007BFF", fg="white").pack(side="left", padx=5)
label_file = Label(file_frame, text="No file selected", bg="#f5f5f5", anchor="w", wraplength=200)
label_file.pack(side="left", padx=5)

# Encryption Key Frame
encrypt_frame = Frame(root, bg="#f5f5f5")
encrypt_frame.pack(pady=10, fill="x", padx=10)
Label(encrypt_frame, text="Enter Encryption Key:", bg="#f5f5f5").pack(anchor="w", padx=5)
key_entry_encrypt = Entry(encrypt_frame, show="*", width=30)
key_entry_encrypt.pack(anchor="w", padx=5, pady=5)
Button(encrypt_frame, text="Enter Key", command=enter_key_encrypt, width=15, bg="#007BFF", fg="white").pack(pady=5)

Button(root, text="Encrypt File", command=encrypt_file, width=20, bg="#28A745", fg="white").pack(pady=10)

# Decryption Key Frame
decrypt_frame = Frame(root, bg="#f5f5f5")
decrypt_frame.pack(pady=10, fill="x", padx=10)
Label(decrypt_frame, text="Enter Decryption Key:", bg="#f5f5f5").pack(anchor="w", padx=5)
key_entry_decrypt = Entry(decrypt_frame, show="*", width=30)
key_entry_decrypt.pack(anchor="w", padx=5, pady=5)
Button(decrypt_frame, text="Enter Key", command=enter_key_decrypt, width=15, bg="#007BFF", fg="white").pack(pady=5)

Button(root, text="Decrypt File", command=decrypt_file, width=20, bg="#28A745", fg="white").pack(pady=10)

# Footer
Label(root, text="Developed by Manjusha", font=("Arial", 10), bg="#f5f5f5", fg="gray").pack(pady=15)

root.mainloop()
