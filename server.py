import socket
import ssl
import json
import os
import uuid
import zipfile
import datetime
import base64
import logging
from secure_storage import SecureFileStorage  # Assuming this is your SecureFileStorage class

# Setup logging for better error tracking
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Load environment variables
server_host = "0.0.0.0"
server_port = int(os.getenv('PORT', 5000))  # Default port is 5000 if the env variable is not set
server_cert = "certs/server.crt"
server_key = "certs/server.key"
ca_cert = "certs/ca.crt"

# Dictionary to simulate users and their credentials
users = {"user1": "password1", "user2": "password2"}
sessions = {}  # Store active sessions

# Dictionary to store SecureFileStorage instances based on session IDs
secure_storage = {}

# Ensure storage directory exists for archives
os.makedirs('secure_storage', exist_ok=True)

def create_secure_socket():
    """Create a secure SSL socket."""
    try:
        # Create an SSL context to secure the socket
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=server_cert, keyfile=server_key)
        context.load_verify_locations(cafile=ca_cert)
        secure_socket = context.wrap_socket(socket.socket(socket.AF_INET), server_side=True)
        secure_socket.bind((server_host, server_port))
        secure_socket.listen(5)
        logging.info(f"Server listening on {server_host}:{server_port}")
        return secure_socket
    except Exception as e:
        logging.error(f"Error creating secure socket: {e}")
        raise

def parse_headers(request_data):
    """Parse headers from the raw request data."""
    headers = {}
    try:
        lines = request_data.split("\r\n")
        for line in lines[1:]:
            if ": " in line:
                key, value = line.split(": ", 1)
                headers[key] = value
    except Exception as e:
        logging.error(f"Error parsing headers: {e}")
    return headers

def send_response(client_socket, status_code, body):
    """Send an HTTP response to the client."""
    try:
        status_messages = {200: "OK", 401: "Unauthorized", 403: "Forbidden", 400: "Bad Request", 404: "Not Found"}
        status_text = status_messages.get(status_code, "Internal Server Error")
        body_json = json.dumps(body)
        response = f"HTTP/1.1 {status_code} {status_text}\r\n"
        response += "Content-Type: application/json\r\n"
        response += f"Content-Length: {len(body_json)}\r\n"
        response += "\r\n"
        response += body_json
        client_socket.sendall(response.encode())
    except Exception as e:
        logging.error(f"Error sending response: {e}")

def handle_login(client_socket, request_data):
    """Handle login requests."""
    body = request_data.split("\r\n\r\n")[1] if "\r\n\r\n" in request_data else ""
    try:
        data = json.loads(body)
        username = data.get("username")
        password = data.get("password")

        if users.get(username) == password:
            session_id = str(uuid.uuid4())  # Create a new session ID
            sessions[session_id] = username
            secure_storage[session_id] = SecureFileStorage(password)  # Create a new secure storage object for the user
            send_response(client_socket, 200, {"message": "Login successful!", "session_id": session_id})
        else:
            send_response(client_socket, 401, {"message": "Invalid credentials"})
    except json.JSONDecodeError:
        send_response(client_socket, 400, {"message": "Invalid JSON format"})
    except Exception as e:
        logging.error(f"Error handling login: {e}")
        send_response(client_socket, 500, {"message": "Internal Server Error"})

def handle_file_upload(client_socket, headers, request_data):
    """Handle file upload requests and securely store the file."""
    session_id = headers.get("Authorization")
    try:
        if session_id not in sessions:
            send_response(client_socket, 403, {"message": "Unauthorized"})
            return

        file_name = headers.get("File-Name")
        if file_name:
            body = request_data.split("\r\n\r\n")[1] if "\r\n\r\n" in request_data else ""
            secure_storage[session_id].store_file(file_name, body.encode())  # Store the file securely
            secure_storage[session_id].encrypt_archive()  # Encrypt the files after storing them
            secure_storage[session_id].save_encrypted_archive(f"archive_{session_id}")  # Save encrypted archive to disk
            send_response(client_socket, 200, {"message": "File uploaded successfully."})
        else:
            send_response(client_socket, 400, {"message": "No file name provided"})
    except Exception as e:
        logging.error(f"Error handling file upload: {e}")
        send_response(client_socket, 500, {"message": "Internal Server Error"})

def handle_get_files(client_socket, headers):
    """Handle request to list available archives."""
    session_id = headers.get("Authorization")
    try:
        if session_id not in sessions:
            send_response(client_socket, 403, {"message": "Unauthorized"})
            return

        # List all available archives
        archive_files = []
        for file_name in os.listdir('secure_storage'):
            if file_name.endswith('.enc'):
                archive_files.append(file_name)

        if archive_files:
            send_response(client_socket, 200, {"archives": archive_files})
        else:
            send_response(client_socket, 404, {"message": "No archives found"})
    except Exception as e:
        logging.error(f"Error handling get files: {e}")
        send_response(client_socket, 500, {"message": "Internal Server Error"})

def handle_download_file(client_socket, headers):
    """Handle file download requests."""
    session_id = headers.get("Authorization")
    file_name = headers.get("File-Name")
    try:
        if session_id not in sessions or not file_name:
            send_response(client_socket, 403, {"message": "Unauthorized or missing file name"})
            return

        # Check if the requested file exists
        file_path = os.path.join('secure_storage', file_name)
        if os.path.exists(file_path):
            with open(file_path, 'rb') as f:
                file_data = f.read()
                encoded_data = base64.b64encode(file_data).decode('utf-8')
                send_response(client_socket, 200, {"message": "File downloaded", "file_content": encoded_data})

        else:
            send_response(client_socket, 404, {"message": "File not found"})
    except Exception as e:
        logging.error(f"Error handling file download: {e}")
        send_response(client_socket, 500, {"message": "Internal Server Error"})

def handle_client(client_socket):
    """Handle the incoming client requests."""
    try:
        request_data = client_socket.recv(4096).decode('utf-8', errors='ignore')
        logging.info(f"Request received:\n{request_data}")
        headers = parse_headers(request_data)

        if "POST /login" in request_data:
            handle_login(client_socket, request_data)
        elif "POST /upload-file" in request_data:
            handle_file_upload(client_socket, headers, request_data)
        elif "GET /get-files" in request_data:
            handle_get_files(client_socket, headers)
        elif "GET /download-file" in request_data:
            handle_download_file(client_socket, headers)

    except Exception as err:
        logging.error(f"Unexpected error: {err}")
        send_response(client_socket, 500, {"message": "Internal Server Error"})
    finally:
        client_socket.close()

def start_server():
    """Start the server to listen for client connections."""
    server_socket = create_secure_socket()

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            logging.info(f"Connection established with {client_address}")
            handle_client(client_socket)
        except Exception as e:
            logging.error(f"Error accepting connection: {e}")

if __name__ == "__main__":
    start_server()

