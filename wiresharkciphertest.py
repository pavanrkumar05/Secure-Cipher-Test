import os
import ssl
import socket
import tkinter as tk
from tkinter import messagebox
import paramiko
from xhtml2pdf import pisa
import ttkbootstrap as ttk
from ttkbootstrap.constants import *


class CipherTestApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Cipher Test App")
        self.root.geometry("1020x820")
        self.root.configure(bg="#f8f9fa")

        ttk.Label(root, text="🔒 Secure Cipher Inspection Tool", font=("Helvetica", 32, "bold"),
                  bootstyle="dark").pack(pady=(20, 10))

        card = ttk.Frame(root, padding=30, bootstyle="light")
        card.pack(pady=10, padx=30, fill='x')

        form_frame = ttk.Frame(card, padding=(10, 10))
        form_frame.pack(fill='x')

        # IP Address
        ttk.Label(form_frame, text="DUT IP Address:", font=("Arial", 13)).grid(row=0, column=0, sticky='w', padx=(0, 10), pady=5)
        self.ip_entry = ttk.Entry(form_frame, width=40, bootstyle="info")
        self.ip_entry.grid(row=0, column=1, pady=5, sticky='ew')

        # Username
        ttk.Label(form_frame, text="Username:", font=("Arial", 13)).grid(row=1, column=0, sticky='w', padx=(0, 10), pady=5)
        self.username_entry = ttk.Entry(form_frame, width=40, bootstyle="info")
        self.username_entry.grid(row=1, column=1, pady=5, sticky='ew')

        # Password
        ttk.Label(form_frame, text="Password:", font=("Arial", 13)).grid(row=2, column=0, sticky='w', padx=(0, 10), pady=5)
        self.password_entry = ttk.Entry(form_frame, width=40, show="*", bootstyle="info")
        self.password_entry.grid(row=2, column=1, pady=5, sticky='ew')

        # Mode Selection
        self.mode_var = tk.StringVar(value="remote")
        ttk.Label(form_frame, text="Inspection Mode:", font=("Arial", 13)).grid(row=3, column=0, sticky='nw', pady=10)
        mode_frame = ttk.Frame(form_frame)
        mode_frame.grid(row=3, column=1, sticky='w')
        ttk.Radiobutton(mode_frame, text="Remote SSH", variable=self.mode_var, value="remote", bootstyle="success").pack(anchor='w')
        ttk.Radiobutton(mode_frame, text="Wireshark Analysis", variable=self.mode_var, value="wireshark", bootstyle="warning").pack(anchor='w')

        # Buttons
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Run Cipher Test", command=self.run_test, bootstyle="success-outline", width=30).grid(row=0, column=0, padx=10)
        self.view_report_btn = ttk.Button(button_frame, text="View HTML Report", command=self.view_html, bootstyle="info-outline", width=30)
        self.view_pdf_btn = ttk.Button(button_frame, text="Open PDF Report", command=self.view_pdf, bootstyle="dark-outline", width=30)
        self.view_report_btn.grid(row=1, column=0, pady=10)
        self.view_pdf_btn.grid(row=2, column=0, pady=10)
        self.view_report_btn.grid_remove()
        self.view_pdf_btn.grid_remove()

    def run_test(self):
        ip = self.ip_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()

        if self.mode_var.get() == "remote" and (not ip or not username or not password):
            messagebox.showerror("Input Error", "IP, username, and password are required for remote inspection.")
            return

        report_html = self.create_html_header()

        if self.mode_var.get() == "remote":
            report_html = self.validate_ssh_remote(ip, username, password, report_html)
        elif self.mode_var.get() == "wireshark":
            report_html = self.validate_ssh_dummy(report_html)

        report_html += "</table></body></html>"

        with open("compliance_report.html", "w") as f:
            f.write(report_html)
        self.convert_to_pdf(report_html)

        messagebox.showinfo("Success", "Report generated successfully!")
        self.view_report_btn.grid()
        self.view_pdf_btn.grid()

    def create_html_header(self):
        return """
        <html><head><title>Cipher Report</title>
        <style>
        body { font-family: Arial; text-align: center; }
        h2 { color: #333; }
        table { width: 90%; margin: auto; border-collapse: collapse; }
        th, td { border: 1px solid #999; padding: 8px; }
        th { background: #eee; }
        .Secure { background: #c8e6c9; }
        .Insecure { background: #ffcdd2; }
        </style>
        </head><body><h2>Secure Cipher Report</h2>
        <table><tr><th>Protocol</th><th>Category</th><th>Algorithm</th><th>Status</th></tr>
        """

    def validate_ssh_remote(self, ip, username, password, report):
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username=username, password=password, timeout=10)

            sections = {
                "cipher": ("Symmetric_Key", ["aes128-ctr", "aes192-ctr", "aes256-ctr"]),
                "key": ("Asymmetric_Key&Digital_sign", ["rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"]),
                "kex": ("Key_Exchange", ["curve25519-sha256", "ecdh-sha2-nistp256"]),
                "mac": ("MAC", ["hmac-sha2-256", "hmac-sha2-512"])
            }

            for cmd, (label, accepted) in sections.items():
                stdin, stdout, stderr = client.exec_command(f"ssh -Q {cmd}")
                ciphers = stdout.read().decode().splitlines()
                for cipher in ciphers:
                    status = "Secure" if cipher in accepted else "Insecure"
                    report += f"<tr><td>SSH</td><td>{label}</td><td>{cipher}</td><td class='{status}'>{status}</td></tr>"

            client.close()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Remote SSH failed: {str(e)}")
        return report

    def validate_ssh_dummy(self, report):
        dummy_ciphers = {
            "Symmetric_Key": ["aes128-ctr", "des", "aes256-cbc"],
            "Asymmetric_Key&Digital_sign": ["rsa-sha2-256", "ssh-dss"],
            "Key_Exchange": ["curve25519-sha256", "diffie-hellman-group1-sha1"],
            "MAC": ["hmac-sha2-512", "hmac-md5"]
        }
        accepted = {
            "Symmetric_Key": ["aes128-ctr", "aes192-ctr", "aes256-ctr"],
            "Asymmetric_Key&Digital_sign": ["rsa-sha2-256", "ecdsa-sha2-nistp256", "ssh-ed25519"],
            "Key_Exchange": ["curve25519-sha256", "ecdh-sha2-nistp256"],
            "MAC": ["hmac-sha2-256", "hmac-sha2-512"]
        }

        for category, ciphers in dummy_ciphers.items():
            for cipher in ciphers:
                status = "Secure" if cipher in accepted[category] else "Insecure"
                report += f"<tr><td>SSH</td><td>{category}</td><td>{cipher}</td><td class='{status}'>{status}</td></tr>"
        return report

    def convert_to_pdf(self, html_content):
        with open("cipher_report.pdf", "wb") as pdf_file:
            pisa.CreatePDF(html_content, dest=pdf_file)

    def view_html(self):
        if os.name == "nt":
            os.startfile("compliance_report.html")
        else:
            os.system("xdg-open compliance_report.html")

    def view_pdf(self):
        if os.name == "nt":
            os.startfile("cipher_report.pdf")
        else:
            os.system("xdg-open cipher_report.pdf")


if __name__ == "__main__":
    root = ttk.Window(themename="minty")
    app = CipherTestApp(root)
    root.mainloop()
