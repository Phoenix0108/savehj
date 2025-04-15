import os
import io
import zipfile
import datetime
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class SecureFileStorage:
    def __init__(self, password: str, storage_dir="secure_storage"):
        self.password = password.encode()
        self.key = hashlib.sha256(self.password).digest()
        self.archive_buffer = io.BytesIO()
        self.encrypted_buffer = None
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)

    def store_file(self, file_name: str, file_data: bytes):
        with zipfile.ZipFile(self.archive_buffer, 'a', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(file_name, file_data)

    def encrypt_archive(self):
        data = self.archive_buffer.getvalue()
        cipher = AES.new(self.key, AES.MODE_CBC)
        encrypted = cipher.iv + cipher.encrypt(pad(data, AES.block_size))
        self.encrypted_buffer = io.BytesIO(encrypted)
        self.archive_buffer = io.BytesIO()  # Reset
        print("Archive encrypted.")

    def save_encrypted_archive(self, archive_name: str):
        if not self.encrypted_buffer:
            raise ValueError("No encrypted archive to save.")
        path = os.path.join(self.storage_dir, f"{archive_name}.enc")
        with open(path, "wb") as f:
            f.write(self.encrypted_buffer.getvalue())
        print(f"Saved encrypted archive: {path}")

    def load_encrypted_archive(self, archive_name: str):
        path = os.path.join(self.storage_dir, f"{archive_name}.enc")
        if not os.path.exists(path):
            raise FileNotFoundError(f"{path} not found.")
        with open(path, "rb") as f:
            self.encrypted_buffer = io.BytesIO(f.read())
        print(f"Loaded archive: {path}")

    def decrypt_archive(self):
        if not self.encrypted_buffer:
            raise ValueError("No archive loaded.")
        data = self.encrypted_buffer.getvalue()
        iv, encrypted = data[:AES.block_size], data[AES.block_size:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted), AES.block_size)
        self.archive_buffer = io.BytesIO(decrypted)
        print("Archive decrypted.")

    def extract_files(self):
        if self.archive_buffer.getvalue() == b"":
            raise ValueError("No decrypted data.")
        files = {}
        with zipfile.ZipFile(self.archive_buffer) as archive:
            for name in archive.namelist():
                files[name] = archive.read(name)
        print("Files extracted.")
        return files

