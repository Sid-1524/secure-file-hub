import os
import sqlite3
import uuid
import bcrypt
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote

# ======= CONFIGURATION =======
DB_DIR = r"D:\Coding\Server"
DB_PATH = os.path.join(DB_DIR, "file_server.db")
UPLOAD_ROOT = os.path.join(DB_DIR, "user_files")

os.makedirs(DB_DIR, exist_ok=True)
os.makedirs(UPLOAD_ROOT, exist_ok=True)

# ======= SERVER HANDLER =======
class FileServerHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200, content_type="text/plain"):
        self.send_response(status)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def _authenticate(self):
        token = self.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            return None
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''SELECT user_id FROM sessions 
                      WHERE token = ? AND datetime(expires) > datetime('now')''',
                    (token,))
            result = c.fetchone()
            return result[0] if result else None

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/register":
            self._handle_register()
        elif path == "/login":
            self._handle_login()
        elif path == "/upload":
            self._handle_upload()
        elif path == "/delete":
            self._handle_delete()
        else:
            self._set_headers(404)
            self.wfile.write(b"Endpoint not found")

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/list":
            self._handle_list_files()
        elif path.startswith("/download/"):
            self._handle_download(unquote(path[len("/download/"):]))
        else:
            self._set_headers(404)
            self.wfile.write(b"Endpoint not found")

    def _handle_register(self):
        data = self._read_json()
        user_id = data.get("user_id")
        password = data.get("password")
        if not user_id or not password:
            return self._send_json({"error": "Missing credentials"}, 400)
        try:
            hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
            with sqlite3.connect(DB_PATH) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO users VALUES (?, ?)', (user_id, hashed_pw))
                conn.commit()
            os.makedirs(os.path.join(UPLOAD_ROOT, user_id), exist_ok=True)
            self._send_json({"status": "Registered successfully"})
        except sqlite3.IntegrityError:
            self._send_json({"error": "User already exists"}, 409)

    def _handle_login(self):
        data = self._read_json()
        user_id = data.get("user_id")
        password = data.get("password")
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('SELECT password_hash FROM users WHERE id = ?', (user_id,))
            result = c.fetchone()
            if not result or not bcrypt.checkpw(password.encode(), result[0]):
                return self._send_json({"error": "Invalid credentials"}, 401)
            token = str(uuid.uuid4())
            c.execute('INSERT INTO sessions VALUES (?, ?, datetime("now", "+1 hour"))', (token, user_id))
            conn.commit()
            self._send_json({"token": token, "user_id": user_id})

    def _handle_upload(self):
        user_id = self._authenticate()
        if not user_id:
            return self._send_json({"error": "Unauthorized"}, 401)
        filename = self.headers.get("X-Filename")
        if not filename:
            return self._send_json({"error": "Missing filename"}, 400)
        file_path = os.path.join(UPLOAD_ROOT, user_id, filename)
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        content_length = int(self.headers['Content-Length'])
        with open(file_path, "wb") as f:
            f.write(self.rfile.read(content_length))
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('INSERT OR REPLACE INTO files VALUES (?, ?, ?)', (filename, user_id, file_path))
            conn.commit()
        self._send_json({"status": "File uploaded"})

    def _handle_delete(self):
        user_id = self._authenticate()
        if not user_id:
            return self._send_json({"error": "Unauthorized"}, 401)
        data = self._read_json()
        filename = data.get("filename")
        if not filename:
            return self._send_json({"error": "Missing filename"}, 400)
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('SELECT path FROM files WHERE filename = ? AND user_id = ?', (filename, user_id))
            result = c.fetchone()
            if not result:
                return self._send_json({"error": "File not found"}, 404)
            file_path = result[0]
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                c.execute('DELETE FROM files WHERE filename = ? AND user_id = ?', (filename, user_id))
                conn.commit()
                self._send_json({"status": "File deleted"})
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

    def _handle_list_files(self):
        user_id = self._authenticate()
        if not user_id:
            return self._send_json({"error": "Unauthorized"}, 401)
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('SELECT filename FROM files WHERE user_id = ?', (user_id,))
            files = [row[0] for row in c.fetchall()]
            self._send_json({"files": files})

    def _handle_download(self, filename):
        user_id = self._authenticate()
        if not user_id:
            return self._send_json({"error": "Unauthorized"}, 401)
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('SELECT path FROM files WHERE filename = ? AND user_id = ?', (filename, user_id))
            result = c.fetchone()
            if not result or not os.path.exists(result[0]):
                return self._send_json({"error": "File not found"}, 404)
            self._set_headers(200, "application/octet-stream")
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            with open(result[0], "rb") as f:
                self.wfile.write(f.read())

    def _read_json(self):
        content_length = int(self.headers['Content-Length'])
        return json.loads(self.rfile.read(content_length).decode())

    def _send_json(self, data, status=200):
        self._set_headers(status, "application/json")
        self.wfile.write(json.dumps(data).encode())

if __name__ == "__main__":
    from database import init_db, create_admin_user
    init_db()
    create_admin_user()
    print(f"Server running at http://0.0.0.0:8000")
    print(f"Database: {DB_PATH}")
    print(f"User files: {UPLOAD_ROOT}")
    server = HTTPServer(('0.0.0.0', 8000), FileServerHandler)
    server.serve_forever()
