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
        """Calculate SHA-512 hash of a file."""
        sha512_hash = hashlib.sha512()
        try:
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha512_hash.update(byte_block)
            return sha512_hash.hexdigest()
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
