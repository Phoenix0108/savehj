import socket
import ssl
import json
import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from datetime import datetime, timedelta
import threading
import time
import schedule
from secure_storage import SecureFileStorage

CONFIG_FILE = "config.json"
UPLOAD_SCHEDULE_FILE = "upload_schedule.json"

# --- Globals (set via login screen) ---
server_host = ""
server_port = 0
username = ""
user_password = ""

client_cert = "certs/client.crt"
client_key = "certs/client.key"
ca_cert = "certs/ca.crt"

# --- Config & Schedule Persistence ---
def save_config(config_data):
    with open(CONFIG_FILE, "w") as f:
        json.dump(config_data, f)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    return {}

def save_schedule(schedule_data):
    with open(UPLOAD_SCHEDULE_FILE, "w") as f:
        json.dump(schedule_data, f)

def load_schedule():
    if os.path.exists(UPLOAD_SCHEDULE_FILE):
        with open(UPLOAD_SCHEDULE_FILE, "r") as f:
            return json.load(f)
    return {}

upload_schedule = load_schedule()

# --- Networking & Server Communication ---
def create_secure_socket():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)
    context.load_verify_locations(cafile=ca_cert)
    context.verify_mode = ssl.CERT_REQUIRED
    secure_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server_host)
    secure_socket.connect((server_host, server_port))
    return secure_socket

def send_request(secure_socket, request_data):
    secure_socket.sendall(request_data.encode())
    response = secure_socket.recv(8192).decode()
    return response

def login_to_server():
    secure_socket = create_secure_socket()
    login_data = {"username": username, "password": user_password}
    request_data = f"POST /login HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: {len(json.dumps(login_data))}\r\n\r\n{json.dumps(login_data)}"
    response = send_request(secure_socket, request_data)
    secure_socket.close()
    print(response)

    try:
        body = response.split("\r\n\r\n")[1]
        session_id = json.loads(body).get("session_id")
        return session_id
    except:
        return None

def upload_file(session_id, file_path):
    if not file_path:
        return "No file selected"

    file_name = os.path.basename(file_path)
    with open(file_path, "rb") as f:
        file_content = f.read()

    secure_socket = create_secure_socket()
    request_data = f"POST /upload-file HTTP/1.1\r\nAuthorization: {session_id}\r\nFile-Name: {file_name}\r\nContent-Length: {len(file_content)}\r\n\r\n"
    secure_socket.sendall(request_data.encode() + file_content)
    response = secure_socket.recv(4096).decode()
    secure_socket.close()
    return response

def list_files(session_id):
    secure_socket = create_secure_socket()
    request_data = f"GET /get-files HTTP/1.1\r\nAuthorization: {session_id}\r\n\r\n"
    response = send_request(secure_socket, request_data)
    secure_socket.close()

    try:
        body = response.split("\r\n\r\n")[1]
        return json.loads(body).get("archives", [])
    except:
        return []

def download_and_decrypt_file(session_id, file_name):
    secure_socket = create_secure_socket()
    request_data = f"GET /download-file HTTP/1.1\r\nAuthorization: {session_id}\r\nFile-Name: {file_name}\r\n\r\n"
    response = send_request(secure_socket, request_data)
    secure_socket.close()

    try:
        response_json = json.loads(response.split("\r\n\r\n")[1])
        encrypted_content = base64.b64decode(response_json["file_content"])
    except Exception as e:
        messagebox.showerror("Error", f"Failed to parse file: {e}")
        return

    os.makedirs("downloads", exist_ok=True)
    enc_path = f"downloads/{file_name}"
    with open(enc_path, "wb") as f:
        f.write(encrypted_content)

    secure_storage = SecureFileStorage(password=user_password, storage_dir="downloads")
    secure_storage.load_encrypted_archive(file_name[:-4])

    try:
        secure_storage.decrypt_archive()
        extracted_files = secure_storage.extract_files()
    except Exception as e:
        messagebox.showerror("Decryption Error", str(e))
        return

    for fname, content in extracted_files.items():
        path = f"downloads/decrypted_{fname}"
        with open(path, "wb") as f:
            f.write(content)
    messagebox.showinfo("Success", f"Decrypted and saved: {len(extracted_files)} file(s).")

# --- Background Upload Scheduler ---
def check_and_upload_scheduled_files(session_id):
    global upload_schedule
    now = time.time()
    updated = False

    for file_path, last_upload in upload_schedule.items():
        if os.path.exists(file_path) and now - last_upload >= 86400:
            try:
                upload_file(session_id, file_path)
                upload_schedule[file_path] = time.time()
                updated = True
            except Exception as e:
                print(f"Scheduled upload failed for {file_path}: {e}")

    if updated:
        save_schedule(upload_schedule)

def start_scheduler(session_id):
    def job():
        check_and_upload_scheduled_files(session_id)

    schedule.every(1).minutes.do(job)

    def scheduler_thread():
        while True:
            schedule.run_pending()
            time.sleep(10)

    thread = threading.Thread(target=scheduler_thread, daemon=True)
    thread.start()

# --- UI Setup ---
def main_ui(session_id):
    root = tk.Tk()
    root.title("Secure File Client")
    root.configure(bg="#1e1e1e")
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    root.geometry(f"{screen_width}x{screen_height}")
    root.resizable(True, True)

    font_large = ("Consolas", 14)
    fg_color = "#ffffff"
    warn_color = "#ff5555"

    left_frame = tk.Frame(root, bg="#2e2e2e", width=600)
    right_frame = tk.Frame(root, bg="#1e1e1e")
    left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=False)
    right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    tk.Label(left_frame, text="Files on Server", fg=fg_color, bg="#2e2e2e", font=("Consolas", 18)).pack(pady=10)
    file_listbox = tk.Listbox(left_frame, width=60, bg="#1e1e1e", fg=fg_color, font=font_large, selectbackground="#333333")
    file_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def update_file_list():
        file_listbox.delete(0, tk.END)
        archives = list_files(session_id)
        now = datetime.now()

        for archive in archives:
            try:
                name_part = archive.rsplit("_", 1)
                timestamp_str = name_part[1].replace(".enc", "").replace("T", " ")
                dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H-%M-%S")
                age = now - dt
                warning = " ⚠ (over 24h)" if age > timedelta(hours=24) else ""
                display = f"{archive} | Last upload: {dt.strftime('%Y-%m-%d %H:%M:%S')}{warning}"
            except Exception:
                display = f"{archive} | Last upload: Unknown"

            file_listbox.insert(tk.END, display)

    def upload_button_click():
        file_path = filedialog.askopenfilename()
        if file_path:
            response = upload_file(session_id, file_path)
            messagebox.showinfo("Upload Response", response)
            update_file_list()

    def schedule_upload():
        file_path = filedialog.askopenfilename()
        if file_path:
            upload_schedule[file_path] = 0
            save_schedule(upload_schedule)
            messagebox.showinfo("Scheduled", f"Scheduled file for daily upload: {file_path}")

    def download_selected():
        selected = file_listbox.curselection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a file to download.")
            return
        item_text = file_listbox.get(selected[0])
        filename = item_text.split(" | ")[0]
        download_and_decrypt_file(session_id, filename)

    tk.Label(right_frame, text="Actions", fg=fg_color, bg="#1e1e1e", font=("Consolas", 18)).pack(pady=20)
    tk.Button(right_frame, text="Upload File", font=font_large, bg="#3e3e3e", fg=fg_color, command=upload_button_click).pack(pady=10, ipadx=10)
    tk.Button(right_frame, text="Schedule File for Daily Upload", font=font_large, bg="#3e3e3e", fg=fg_color, command=schedule_upload).pack(pady=10, ipadx=10)
    tk.Button(right_frame, text="Download Selected", font=font_large, bg="#3e3e3e", fg=fg_color, command=download_selected).pack(pady=10, ipadx=10)
    tk.Button(right_frame, text="Refresh List", font=font_large, bg="#3e3e3e", fg=fg_color, command=update_file_list).pack(pady=10, ipadx=10)
    tk.Button(right_frame, text="Exit", font=font_large, bg=warn_color, fg="#ffffff", command=root.destroy).pack(pady=40, ipadx=10)

    update_file_list()
    start_scheduler(session_id)
    root.mainloop()

def login_ui():
    def submit():
        nonlocal login_window
        global server_host, server_port, username, user_password

        server_host = entry_host.get()
        server_port = int(entry_port.get())
        username = entry_user.get()
        user_password = entry_pass.get()

        session = login_to_server()
        if session:
            if remember_var.get():
                save_config({
                    "host": server_host,
                    "port": server_port,
                    "username": username,
                    "password": user_password
                })
            login_window.destroy()
            main_ui(session)
        else:
            messagebox.showerror("Login Failed", "Could not authenticate with server.")

    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("400x350")
    login_window.configure(bg="#1e1e1e")

    config = load_config()

    tk.Label(login_window, text="Server IP:", fg="white", bg="#1e1e1e").pack(pady=5)
    entry_host = tk.Entry(login_window)
    entry_host.pack()

    tk.Label(login_window, text="Port:", fg="white", bg="#1e1e1e").pack(pady=5)
    entry_port = tk.Entry(login_window)
    entry_port.pack()

    tk.Label(login_window, text="Username:", fg="white", bg="#1e1e1e").pack(pady=5)
    entry_user = tk.Entry(login_window)
    entry_user.pack()

    tk.Label(login_window, text="Password:", fg="white", bg="#1e1e1e").pack(pady=5)
    entry_pass = tk.Entry(login_window, show="*")
    entry_pass.pack()

    remember_var = tk.IntVar()
    tk.Checkbutton(login_window, text="Remember Me", variable=remember_var, bg="#1e1e1e", fg="white").pack(pady=5)

    if config:
        entry_host.insert(0, config.get("host", ""))
        entry_port.insert(0, str(config.get("port", "")))
        entry_user.insert(0, config.get("username", ""))
        entry_pass.insert(0, config.get("password", ""))
        remember_var.set(1)

    tk.Button(login_window, text="Login", command=submit).pack(pady=20)
    login_window.mainloop()

if __name__ == "__main__":
    login_ui()
