# Intrusion Detection System using Hash Functions

## Overview
The Intrusion Detection System (IDS) monitors system logs and network activity using SHA-based integrity verification. It detects unauthorized modifications, helping to prevent cyberattacks such as malware injections and unauthorized access.

## Features
- **Real-time Log Monitoring**: Continuously scans system logs and network activity.
- **Hash-Based Integrity Verification**: Uses SHA-256 to detect tampering.
- **Automated Alerts**: Notifies administrators of unauthorized changes.
- **Lightweight & Efficient**: Minimal resource usage while ensuring security.
- **Customizable Logging**: Configurable monitoring for different system components.

## Installation
### Prerequisites
Ensure you have the following installed:
- **Python 3.x**
- **Required dependencies**: Install using:
  ```sh
  pip install hashlib watchdog
  ```

## Usage
1. **Clone the repository**:
   ```sh
   git clone https://github.com/yourusername/intrusion-detection-system.git
   cd intrusion-detection-system
   ```
2. **Run the IDS script**:
   ```sh
   python main.py
   ```
3. **Monitor logs for security alerts**.

## How It Works
1. Collects system logs & network activity.
2. Computes SHA-256 hash values for logs.
3. Compares new hash values with stored hashes:
   - ✅ If match → Logs remain unchanged; continue monitoring.
   - ❌ If mismatch → Possible tampering; trigger alert & log event.
4. Notifies the administrator of any unauthorized changes.
5. Provides insights for security measures.

## Contributing
We welcome contributions! Please follow these steps:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit changes and push to your fork.
4. Open a pull request.

## License
This project is licensed under the **MIT License**. See `LICENSE` for details.

## Contact
For inquiries, reach out via email or open an issue on [GitHub](https://github.com/yourusername/intrusion-detection-system).

### Email
For direct contact, email us at: **koushikgadirajueshwar@gmail.com**

