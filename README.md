# Secure File Hub (Python Socket Version)

A self-hosted, cross-platform file storage and sharing solution featuring:

- Python socket server with multi-user support
- Modern Tkinter desktop GUI client
- Local network access for uploading, downloading, and deleting files

---

## Features

- User registration and login (with hashed passwords)
- Upload, download, and delete files
- Multi-user support with user-specific storage
- Desktop GUI (Tkinter) for easy file management
- Local network access (connect from any device on your LAN)
- Simple, robust Python socket programming (no Flask, no Docker)

---

## Directory Structure

```
D:\Coding\Server\
├── server.py            # Python socket server
├── database.py          # Database initialization script
├── file_hub_gui.py      # Tkinter desktop GUI client
├── file_server.db       # SQLite database
├── user_files/          # User file storage
└── README.md            # This file
```

---

## Quick Start

### 1. Clone or Download the Project

```
git clone https://github.com/Sid-1524/secure-file-hub.git
cd secure-file-hub
```

### 2. Install Requirements

```
pip install bcrypt requests
```

### 3. Initialize the Database

```
python database.py
```

### 4. Run the Socket Server

```
python server.py
```

- The server will run on your local network (default port, e.g., 5000 or as set in your code).

### 5. Run the Desktop GUI (Optional)

```
python file_hub_gui.py
```

---

## How It Works

- The **server** listens for incoming socket connections, handles authentication, and manages file storage per user.
- The **GUI client** connects to the server, allowing users to register, log in, upload, download, and delete their files.
- All files are stored under `user_files/<username>/` on the server.

---

## Local Network Access

- Ensure your server PC has a **static local IP address** (see your router or Windows network settings).
- Start the server on your PC.
- On any device on the same Wi-Fi/LAN, run the GUI client or a compatible socket client, and connect using the server's local IP and port.

---

## Security Notes

- Use strong passwords for all users.
- The socket server is designed for local network use. For remote/internet access, set up a VPN or secure tunnel.
- Regularly back up your `file_server.db` and `user_files/`.

---

## License

MIT License

---

## Credits

- Python, Tkinter, SQLite, bcrypt

---

## Support

For issues or feature requests, please open an issue on GitHub or contact the maintainer.

---

**Enjoy your private, cross-platform file hub!**


---

## Customizing Database and Upload Directories

You can change the locations of the database file and the directory where user files are stored by modifying the configuration variables in the server code.

### How to Change the Database Location

1. Open `server.py` and `database.py` in a text editor.
2. Locate the configuration variables at the top of each file:

```
# Example in server.py and database.py
DB_DIR = r"D:\\Coding\\Server"
DB_PATH = os.path.join(DB_DIR, "file_server.db")
```

3. Change `DB_DIR` to your desired directory path.
4. Save the files.

### How to Change the Upload Files Directory

1. In `server.py`, locate the `UPLOAD_ROOT` variable:

```
UPLOAD_ROOT = os.path.join(DB_DIR, "user_files")
```

2. Change this to your preferred directory path for storing uploaded files.
3. Save the file.

### Important Notes

- Ensure the directories you specify exist or that the server has permission to create them.
- Use raw strings (`r"path"`) or double backslashes (`"\\"`) for Windows paths to avoid escape character issues.
- After changing these paths, restart your server to apply the changes.

Example:

```
DB_DIR = r"E:\\MyData\\Database"
UPLOAD_ROOT = r"E:\\MyData\\Uploads"
```

This flexibility allows you to organize your data storage according to your preferences or system setup.
```
