import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Listbox, MULTIPLE, END
import requests
import os

SERVER_URL = "http://127.0.0.1:8000"

class FileHubApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Hub")
        self.root.geometry("800x600")
        self.session = requests.Session()
        self.token = None
        self.user_id = None
        self._setup_styles()
        self.show_login()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=6, font=('Helvetica', 10))
        style.configure("Title.TLabel", font=('Helvetica', 14, 'bold'))
        style.configure("Error.TLabel", foreground="red")

    def show_login(self):
        self._clear_window()
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.pack(expand=True)
        ttk.Label(main_frame, text="🔐 Secure File Hub", style="Title.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(main_frame, text="User ID:").grid(row=1, column=0, sticky="w", pady=5)
        self.user_entry = ttk.Entry(main_frame, width=25)
        self.user_entry.grid(row=1, column=1, pady=5, padx=10)
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        self.pass_entry = ttk.Entry(main_frame, show="*", width=25)
        self.pass_entry.grid(row=2, column=1, pady=5, padx=10)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.grid(row=3, column=0, columnspan=2, pady=15)
        ttk.Button(btn_frame, text="Login", command=self.do_login).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Register", command=self.do_register).pack(side="left", padx=10)
        self.status_label = ttk.Label(main_frame, text="", style="Error.TLabel")
        self.status_label.grid(row=4, column=0, columnspan=2)

    def show_file_manager(self):
        self._clear_window()
        header = ttk.Frame(self.root, padding=10)
        header.pack(fill="x")
        ttk.Label(header, text=f"📁 Welcome, {self.user_id}", style="Title.TLabel").pack(side="left")
        ttk.Button(header, text="Logout", command=self.do_logout).pack(side="right")
        action_frame = ttk.Frame(self.root, padding=10)
        action_frame.pack(fill="x")
        ttk.Button(action_frame, text="Upload File", command=self.do_upload).pack(side="left", padx=5)
        ttk.Button(action_frame, text="Refresh", command=self.load_files).pack(side="left", padx=5)
        list_frame = ttk.Frame(self.root)
        list_frame.pack(fill="both", expand=True, padx=10, pady=5)
        self.file_list = Listbox(list_frame, selectmode=MULTIPLE, height=15, font=('Helvetica', 10))
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical")
        self.file_list.configure(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.file_list.yview)
        self.file_list.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        footer = ttk.Frame(self.root, padding=10)
        footer.pack(fill="x")
        ttk.Button(footer, text="Download Selected", command=self.do_download).pack(side="left", padx=5)
        ttk.Button(footer, text="Delete Selected", command=self.do_delete).pack(side="left", padx=5)
        self.load_files()

    def load_files(self):
        self.file_list.delete(0, END)
        try:
            headers = {"Authorization": f"Bearer {self.token}"}
            response = self.session.get(f"{SERVER_URL}/list", headers=headers)
            if response.status_code == 200:
                for file in response.json().get("files", []):
                    self.file_list.insert(END, file)
            else:
                self._show_error(response.json().get("error", "Unknown error"))
        except Exception as e:
            self._show_error(str(e))

    def do_upload(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            return
        try:
            with open(file_path, "rb") as f:
                headers = {
                    "Authorization": f"Bearer {self.token}",
                    "X-Filename": os.path.basename(file_path)
                }
                response = self.session.post(
                    f"{SERVER_URL}/upload",
                    data=f.read(),
                    headers=headers
                )
                if response.status_code == 200:
                    self.load_files()
                else:
                    self._show_error(response.json().get("error", "Upload failed"))
        except Exception as e:
            self._show_error(str(e))

    def do_download(self):
        selections = self.file_list.curselection()
        if not selections:
            self._show_error("No files selected")
            return
        save_dir = filedialog.askdirectory()
        if not save_dir:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        for index in selections:
            filename = self.file_list.get(index)
            try:
                response = self.session.get(
                    f"{SERVER_URL}/download/{filename}",
                    headers=headers
                )
                if response.status_code == 200:
                    with open(os.path.join(save_dir, filename), "wb") as f:
                        f.write(response.content)
                else:
                    self._show_error(f"Failed to download {filename}")
            except Exception as e:
                self._show_error(str(e))
        messagebox.showinfo("Download Complete", "Selected files downloaded")

    def do_delete(self):
        selections = self.file_list.curselection()
        if not selections:
            self._show_error("No files selected")
            return
        confirm = messagebox.askyesno(
            "Confirm Delete", 
            f"Delete {len(selections)} selected file(s)?"
        )
        if not confirm:
            return
        headers = {"Authorization": f"Bearer {self.token}"}
        for index in selections:
            filename = self.file_list.get(index)
            try:
                response = self.session.post(
                    f"{SERVER_URL}/delete",
                    json={"filename": filename},
                    headers=headers
                )
                if response.status_code != 200:
                    self._show_error(f"Failed to delete {filename}")
            except Exception as e:
                self._show_error(str(e))
        self.load_files()

    def do_login(self):
        user_id = self.user_entry.get()
        password = self.pass_entry.get()
        try:
            response = self.session.post(
                f"{SERVER_URL}/login",
                json={"user_id": user_id, "password": password}
            )
            if response.status_code == 200:
                self.token = response.json().get("token")
                self.user_id = user_id
                self.show_file_manager()
            else:
                self._show_error(response.json().get("error", "Login failed"))
        except Exception as e:
            self._show_error(str(e))

    def do_register(self):
        user_id = self.user_entry.get()
        password = self.pass_entry.get()
        try:
            response = self.session.post(
                f"{SERVER_URL}/register",
                json={"user_id": user_id, "password": password}
            )
            if response.status_code == 200:
                messagebox.showinfo("Success", "Registration successful!")
            else:
                self._show_error(response.json().get("error", "Registration failed"))
        except Exception as e:
            self._show_error(str(e))

    def do_logout(self):
        self.token = None
        self.user_id = None
        self.show_login()

    def _clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def _show_error(self, message):
        messagebox.showerror("Error", message)

if __name__ == "__main__":
    root = tk.Tk()
    FileHubApp(root)
    root.mainloop()
