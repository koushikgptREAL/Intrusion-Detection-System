import hashlib
import os
import time
import logging
from datetime import datetime

class IntrusionDetectionSystem:
    def __init__(self, monitored_dirs=None, log_file="D:\\Projects\\IDS_logs\\ids_log.txt"):
        self.monitored_dirs = monitored_dirs if monitored_dirs else ["D:\\Projects\\IDS"]
        self.baseline_hashes = {}
        self.alerts = []
        
        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        
        # Set up logging
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {str(e)}")
            return None

    def create_baseline(self):
        """Create initial baseline of file hashes."""
        self.baseline_hashes.clear()
        for directory in self.monitored_dirs:
            if not os.path.exists(directory):
                os.makedirs(directory)
                self.logger.info(f"Created monitoring directory: {directory}")
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash:
                        self.baseline_hashes[file_path] = file_hash
                        self.logger.info(f"Baseline hash created for {file_path}")

    def check_integrity(self):
        """Check current files against baseline hashes."""
        current_hashes = {}
        for directory in self.monitored_dirs:
            for root, _, files in os.walk(directory):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash:
                        current_hashes[file_path] = file_hash

        for file_path in current_hashes:
            if file_path not in self.baseline_hashes:
                alert = f"New file detected: {file_path}"
                self.alerts.append(alert)
                self.logger.warning(alert)
            elif current_hashes[file_path] != self.baseline_hashes[file_path]:
                alert = f"File modified: {file_path}"
                self.alerts.append(alert)
                self.logger.warning(alert)

        for file_path in self.baseline_hashes:
            if file_path not in current_hashes:
                alert = f"File deleted: {file_path}"
                self.alerts.append(alert)
                self.logger.warning(alert)

    def monitor(self, interval=60):
        """Start continuous monitoring with specified interval in seconds."""
        print("Starting IDS monitoring... Press Ctrl+C to stop.")
        self.create_baseline()
        try:
            while True:
                self.alerts.clear()
                self.check_integrity()
                if self.alerts:
                    print("\nALERTS DETECTED:")
                    for alert in self.alerts:
                        print(f"- {alert}")
                else:
                    print(f"\n[{datetime.now()}] No changes detected")
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            self.logger.info("Monitoring stopped by user")

    def get_logs(self):
        """Return contents of the log file."""
        try:
            with open(self.logger.handlers[0].baseFilename, 'r') as f:
                return f.read()
        except Exception as e:
            return f"Error reading logs: {str(e)}"

if __name__ == "__main__":
    test_dir = "D:\\Projects\\IDS"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    with open(os.path.join(test_dir, "test_file.txt"), "w") as f:
        f.write("This is a test file for IDS")
    ids = IntrusionDetectionSystem(monitored_dirs=[test_dir])
    ids.monitor(interval=5)
    '''
import hashlib
import os
import time
import logging
import smtplib
import socket
import json
from datetime import datetime
from email.mime.text import MIMEText
from cryptography.fernet import Fernet  # For hash encryption
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext

class IntrusionDetectionSystem:
    def __init__(self, monitored_dirs=None, log_file="D:\\Projects\\IDS_logs\\ids_log.txt", email_config=None):
        self.monitored_dirs = monitored_dirs if monitored_dirs else ["D:\\Projects\\IDS"]
        self.baseline_hashes = {}
        self.alerts = []
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        self.email_config = email_config if email_config else {
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "sender_email": "your_email@gmail.com",
            "sender_password": "your_password",
            "receiver_email": "receiver_email@gmail.com"
        }

        # Ensure log directory exists
        log_dir = os.path.dirname(log_file)
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)

        # Set up logging
        logging.basicConfig(
            filename=log_file,
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger()

        # Admin interface
        self.root = tk.Tk()
        self.root.title("IDS Admin Interface")
        self.alert_display = scrolledtext.ScrolledText(self.root, width=80, height=20)
        self.alert_display.pack(padx=10, pady=10)

    def encrypt_hash(self, hash_value):
        """Encrypt a hash value."""
        return self.cipher.encrypt(hash_value.encode()).decode()

    def decrypt_hash(self, encrypted_hash):
        """Decrypt a hash value."""
        return self.cipher.decrypt(encrypted_hash.encode()).decode()

    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of a file."""
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            self.logger.error(f"Error hashing file {file_path}: {str(e)}")
            return None

    def create_baseline(self):
        """Create initial baseline of file hashes with encryption."""
        self.baseline_hashes.clear()
        for directory in self.monitored_dirs:
            if not os.path.exists(directory):
                os.makedirs(directory)
                self.logger.info(f"Created monitoring directory: {directory}")
            for root, _, files in os.walk(directory):
                for filename in files:
                    if filename == "ids_log.txt":
                        continue
                    file_path = os.path.join(root, filename)
                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash:
                        encrypted_hash = self.encrypt_hash(file_hash)
                        self.baseline_hashes[file_path] = encrypted_hash
                        self.logger.info(f"Baseline hash created for {file_path}")

    def monitor_system_logs(self):
        """Monitor system logs (simplified example)."""
        # In a real system, this would monitor actual OS logs (e.g., /var/log)
        log_file = "D:\\Projects\\IDS\\system_log.txt"
        if not os.path.exists(log_file):
            with open(log_file, "w") as f:
                f.write("System log start\n")
        baseline_hash = self.calculate_file_hash(log_file)
        encrypted_baseline = self.encrypt_hash(baseline_hash)
        while True:
            time.sleep(5)
            current_hash = self.calculate_file_hash(log_file)
            if current_hash and self.decrypt_hash(encrypted_baseline) != current_hash:
                alert = f"System log modified: {log_file}"
                self.alerts.append(alert)
                self.logger.warning(alert)
                self.send_email_alert(alert)
                encrypted_baseline = self.encrypt_hash(current_hash)

    def monitor_network_activity(self):
        """Monitor network activity (simplified example)."""
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
            while True:
                packet = s.recvfrom(65565)
                # Simplified: Log packet size as a basic metric
                packet_size = len(packet[0])
                if packet_size > 10000:  # Arbitrary threshold for demo
                    alert = f"Suspicious network activity: Large packet detected ({packet_size} bytes)"
                    self.alerts.append(alert)
                    self.logger.warning(alert)
                    self.send_email_alert(alert)
        except Exception as e:
            self.logger.error(f"Network monitoring error: {str(e)}")

    def check_integrity(self):
        """Check current files against baseline hashes."""
        current_hashes = {}
        for directory in self.monitored_dirs:
            for root, _, files in os.walk(directory):
                for filename in files:
                    if filename == "ids_log.txt":
                        continue
                    file_path = os.path.join(root, filename)
                    file_hash = self.calculate_file_hash(file_path)
                    if file_hash:
                        current_hashes[file_path] = file_hash

        for file_path in current_hashes:
            if file_path not in self.baseline_hashes:
                alert = f"New file detected: {file_path}"
                self.alerts.append(alert)
                self.logger.warning(alert)
                self.send_email_alert(alert)
            elif current_hashes[file_path] != self.decrypt_hash(self.baseline_hashes[file_path]):
                alert = f"File modified: {file_path}"
                self.alerts.append(alert)
                self.logger.warning(alert)
                self.send_email_alert(alert)

        for file_path in self.baseline_hashes:
            if file_path not in current_hashes:
                alert = f"File deleted: {file_path}"
                self.alerts.append(alert)
                self.logger.warning(alert)
                self.send_email_alert(alert)

    def send_email_alert(self, alert):
        """Send email notification for an alert."""
        msg = MIMEText(alert)
        msg['Subject'] = 'IDS Alert'
        msg['From'] = self.email_config["sender_email"]
        msg['To'] = self.email_config["receiver_email"]

        try:
            with smtplib.SMTP(self.email_config["smtp_server"], self.email_config["smtp_port"]) as server:
                server.starttls()
                server.login(self.email_config["sender_email"], self.email_config["sender_password"])
                server.sendmail(self.email_config["sender_email"], self.email_config["receiver_email"], msg.as_string())
                self.logger.info(f"Email alert sent: {alert}")
        except Exception as e:
            self.logger.error(f"Failed to send email alert: {str(e)}")

    def update_admin_interface(self):
        """Update the admin interface with current alerts."""
        self.alert_display.delete(1.0, tk.END)
        for alert in self.alerts:
            self.alert_display.insert(tk.END, f"{alert}\n")

    def monitor(self, interval=5):
        """Start continuous monitoring."""
        print("Starting IDS monitoring... Press Ctrl+C to stop.")
        self.create_baseline()

        # Start system log and network monitoring in separate threads
        log_thread = threading.Thread(target=self.monitor_system_logs)
        network_thread = threading.Thread(target=self.monitor_network_activity)
        log_thread.start()
        network_thread.start()

        try:
            while True:
                self.alerts.clear()
                self.check_integrity()
                if self.alerts:
                    print("\nALERTS DETECTED:")
                    for alert in self.alerts:
                        print(f"- {alert}")
                else:
                    print(f"\n[{datetime.now()}] No changes detected")
                self.update_admin_interface()
                self.root.update()
                time.sleep(interval)
        except KeyboardInterrupt:
            print("\nMonitoring stopped by user")
            self.logger.info("Monitoring stopped by user")
            self.root.destroy()

if __name__ == "__main__":
    test_dir = "D:\\Projects\\IDS"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
    with open(os.path.join(test_dir, "test_file.txt"), "w") as f:
        f.write("This is a test file for IDS")
    
    # Configure email (replace with your details)
    email_config = {
        "smtp_server": "smtp.gmail.com",
        "smtp_port": 587,
        "sender_email": "koushikgadirajueshwar@gmail.com",
        "sender_password": "1234",  # Use an app-specific password for Gmail
        "receiver_email": "realkoushik69@gmail.com"
    }
    
    ids = IntrusionDetectionSystem(monitored_dirs=[test_dir], email_config=email_config)
    ids.monitor(interval=5)'''
    