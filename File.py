import os
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk

def cal_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha256_hash.update(data)
    return sha256_hash.hexdigest()

def check_Integrity(file_path):
    if not os.path.exists(file_path):
        return f"File '{file_path}' Does Not Exist!"

    calculated_hash = cal_sha256(file_path)
    return f"File: {file_path}\nSHA-256 Hash: {calculated_hash}"

class FileIntegrityChecker(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("File Integrity Checker")
        self.geometry("600x400")

        # Create UI elements
        self.file_label = tk.Label(self, text="Select a file to check:")
        self.file_label.pack(pady=10)

        self.file_entry = tk.Entry(self, width=50)
        self.file_entry.pack(pady=5)

        self.browse_button = tk.Button(self, text="Browse", command=self.select_file)
        self.browse_button.pack(pady=5)

        self.check_button = tk.Button(self, text="Check Integrity", command=self.check_integrity)
        self.check_button.pack(pady=10)

        self.output_text = tk.Text(self, width=60, height=10, state="disabled")
        self.output_text.pack(pady=10)

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, file_path)

    def check_integrity(self):
        file_path = self.file_entry.get()
        output = check_Integrity(file_path)
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, output)
        self.output_text.configure(state="disabled")

if __name__ == "__main__":
    app = FileIntegrityChecker()
    app.mainloop()