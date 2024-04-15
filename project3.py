from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from argon2 import PasswordHasher
import os
import base64
import json
import jwt
import datetime
import sqlite3
import uuid

# Environment variable for AES key
NOT_MY_KEY = os.environ.get("NOT_MY_KEY")

# Host and port for the server
hostName = "localhost"
serverPort = 8080

# Initialize SQLite database and connect
db_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create keys table if not exists (modified for encryption)
cursor.execute("""
    CREATE TABLE IF NOT EXISTS keys(
        kid TEXT PRIMARY KEY,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL  -- Ensure 'exp' column is of type INTEGER
    )
""")

# User table for registration and login
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        email TEXT UNIQUE,
        date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP      
    )
""")

# Authentication log table
cursor.execute("""
    CREATE TABLE IF NOT EXISTS auth_logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_ip TEXT NOT NULL,
        request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        user_id INTEGER,  
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
""")

# Generate private keys if the table is empty
cursor.execute("SELECT COUNT(*) FROM keys")
if cursor.fetchone()[0] == 0:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    expired_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Derive encryption key from environment variable
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=390000,
        backend=default_backend()
    )
    encryption_key = base64.urlsafe_b64encode(kdf.derive(NOT_MY_KEY.encode()))

    # Encrypt private keys before storing
    encrypted_pem = encrypt_private_key(private_key)
    expired_encrypted_pem = encrypt_private_key(expired_key)

    # Store encrypted private keys
    if encrypted_pem and expired_encrypted_pem:
        cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", ("goodKID", encrypted_pem, int(datetime.datetime.utcnow().timestamp())))
        cursor.execute("INSERT INTO keys (kid, key, exp) VALUES (?, ?, ?)", ("expiredKID", expired_encrypted_pem, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())))
        conn.commit()
    else:
        print("Error encrypting and storing private keys")

# Function to encrypt private key
def encrypt_private_key(private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.BestAvailableEncryption(encryption_key)
    )
    return pem

# Function to decrypt private key
def decrypt_private_key(encrypted_pem):
    # Decrypt the private key
    private_key = serialization.load_pem_private_key(encrypted_pem, password=None, backend=default_backend())
    return private_key

# Function to hash passwords using Argon2
def hash_password(password):
    ph = PasswordHasher()
    return ph.hash(password)

# Function to verify password hashes
def verify_password_hash(password, hash):
    ph = PasswordHasher()
    try:
        ph.verify(hash, password)
        return True
    except:
        return False

# Function to handle user registration
def register_user(username, email):
    # Validate username and email uniqueness
    cursor.execute("SELECT COUNT(*) FROM users WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone()[0] > 0:
        return {"error": "Username or email already exists"}, 400  # Bad request

    # Generate a secure password (using UUIDv4 is not recommended, replace with a strong password generation method)
    password = str(uuid.uuid4())  # Replace with a secure password generation method

    # Hash the password securely using Argon2
    password_hash = hash_password(password)

    # Insert user data into database
    cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)", (username, password_hash, email))
    conn.commit()

    return {"password": password}, 201  # Created

# Function to log authentication requests
def log_auth_request(request_ip, user_id):
    cursor.execute("INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)", (request_ip, user_id))
    conn.commit()

class MyServer(BaseHTTPRequestHandler):
    def do_PUT(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/register":
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                username = data["username"]
                email = data["email"]
            except (KeyError, json.JSONDecodeError):
                self.send_response(400)
                self.end_headers()
                return
            response, status_code = register_user(username, email)
            self.send_response(status_code)
            self.end_headers()
            self.wfile.write(bytes(json.dumps(response), "utf-8"))
            return

        elif parsed_path.path == "/auth":
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                data = json.loads(post_data)
                username = data["username"]
                password = data["password"]
            except (KeyError, json.JSONDecodeError):
                self.send_response(400)
                self.end_headers()
                return

            # Authenticate user
            cursor.execute("SELECT id, password_hash FROM users WHERE username = ?", (username,))
            user_data = cursor.fetchone()
            if not user_data:
                self.send_response(401)  # Unauthorized
                self.end_headers()
                return

            # Verify password hash
            if not verify_password_hash(password, user_data[1]):
                self.send_response(401)  # Unauthorized
                self.end_headers()
                return

            # Log authentication request
            client_ip = self.client_address[0]
            log_auth_request(client_ip, user_data[0])

            # Generate JWT token
            headers = {"kid": "goodKID"}
            token_payload = {"user": username, "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)}
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            keys = {
                "keys": [
                    {
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "goodKID",
                        "n": int_to_base64(numbers.public_numbers.n),
                        "e": int_to_base64(numbers.public_numbers.e),
                    }
                ]
            }
            self.wfile.write(bytes(json.dumps(keys), "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
