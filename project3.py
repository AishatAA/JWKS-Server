from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3
import uuid
from argon2 import PasswordHasher

# Host and port for the server
hostName = "localhost"
serverPort = 8080

# Initialize SQLite database and connect
db_file = "totally_not_my_privateKeys.db"
conn = sqlite3.connect(db_file)
cursor = conn.cursor()

# Create users table if not exists
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

# Create auth_logs table if not exists
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

    # Serialize private keys into PEM format
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    expired_pem = expired_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Store private keys in the database
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, int(datetime.datetime.utcnow().timestamp())))
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (expired_pem, int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())))
    conn.commit()

# Get private key from the database
cursor.execute("SELECT key FROM keys WHERE exp > ? LIMIT 1", (int(datetime.datetime.utcnow().timestamp()),))
private_key_row = cursor.fetchone()
if private_key_row:
    private_key_bytes = private_key_row[0]
    private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())

numbers = private_key.private_numbers()


def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    # Ensure even length
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')


class MyServer(BaseHTTPRequestHandler):
    # Override methods for various HTTP requests
    
    def do_PUT(self):
        # Respond with Method Not Allowed (405)
        self.send_response(405)
        self.end_headers()
        return

    def do_PATCH(self):
        # Respond with Method Not Allowed (405)
        self.send_response(405)
        self.end_headers()
        return

    def do_DELETE(self):
        # Respond with Method Not Allowed (405)
        self.send_response(405)
        self.end_headers()
        return

    def do_HEAD(self):
        # Respond with Method Not Allowed (405)
        self.send_response(405)
        self.end_headers()
        return

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            # Log the authentication request
            ip_address = self.client_address[0]
            cursor.execute("INSERT INTO auth_logs (request_ip) VALUES (?)", (ip_address,))
            conn.commit()
   
            headers = {
                "kid": "goodKID"
            }
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }
            if 'expired' in params:
                headers["kid"] = "expiredKID"
                token_payload["exp"] = datetime.datetime.utcnow() - datetime.timedelta(hours=1)
            encoded_jwt = jwt.encode(token_payload, pem, algorithm="RS256", headers=headers)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        if parsed_path.path == "/register":
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
           
            # Generate a secure password using UUIDv4
            secure_password = str(uuid.uuid4())

            # Hash the password using Argon2
            ph = PasswordHasher()
            hashed_password = ph.hash(secure_password)

            # Store user details and hashed password in the database
            cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                           (data['username'], hashed_password, data['email']))
            conn.commit()

            # Return the generated password to the user
            self.send_response(201)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"password": secure_password}).encode('utf-8'))
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


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
