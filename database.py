import os
import sqlite3
import bcrypt

# Set your database location
DB_DIR = r"D:\Coding\Server"
DB_PATH = os.path.join(DB_DIR, "file_server.db")

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            # Users table
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL
            )''')
            # Files table
            c.execute('''CREATE TABLE IF NOT EXISTS files (
                filename TEXT,
                user_id TEXT,
                path TEXT,
                PRIMARY KEY(filename, user_id)
            )''')
            # Sessions table
            c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id TEXT,
                expires DATETIME DEFAULT (datetime('now', '+1 hour'))
            )''')
            conn.commit()
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")

def create_admin_user():
    admin_id = "admin"
    password = "admin123"
    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('INSERT OR IGNORE INTO users VALUES (?, ?)', (admin_id, hashed_pw))
            conn.commit()
    except sqlite3.Error as e:
        print(f"Error creating admin user: {e}")

if __name__ == "__main__":
    init_db()
    create_admin_user()
    print(f"Database initialized at {DB_PATH}")
