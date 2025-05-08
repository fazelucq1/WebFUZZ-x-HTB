# WebFUZZ x HTB

🚀 **WebFUZZ x HTB** is a sleek, web-based tool crafted for the initial enumeration of Hack The Box (HTB) machines. Designed for pentesters and CTF enthusiasts, it streamlines reconnaissance with Nmap, FFUF, and Gobuster, delivering results in a clean, interactive HTML report. Input an IP, hit start, and watch the magic happen with real-time progress animations!

## ✨ Features
- **User-Friendly Interface**: Input an IP and kick off enumeration with a single click.
- **Real-Time Feedback**: Animated loading spinners for each phase (Nmap, FFUF Directory, Gobuster Subdomains, FFUF VHosts).
- **Polished Reports**: Automatically generates a modern HTML report with Tailwind CSS styling.
- **Built for HTB**: Tailored for quick and efficient reconnaissance on Hack The Box challenges.
- 
## 🛠️ Prerequisites
- Python 3.8+
- Flask (`pip install flask`)
- Nmap, FFUF, and Gobuster installed (`sudo apt install nmap ffuf gobuster` on Debian-based systems)
- Seclists wordlists (`sudo apt install seclists`)

## 🚀 Getting Started

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/fazelucq1/webfuzz-x-htb.git
   cd webfuzz-x-htb
   ```

2. **Set Up a Virtual Environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install flask
   ```

4. **Ensure Tools Are Installed**:
   Verify that Nmap, FFUF, Gobuster, and Seclists are installed and accessible in your system PATH.

5. **Run the App (with sudo)**:
   ```bash
   sudo python app.py
   ```

6. **Access the Tool**:
   Open your browser and navigate to `http://127.0.0.1:5000`.

## 🎮 Usage
1. Enter the target IP address in the input field.
2. Click **"Avvia Enumerazione"** to start the scan.
3. Watch the animated spinners as WebFUZZ runs Nmap, FFUF, and Gobuster.
4. Once complete, click **"Visualizza Report"** to view the detailed HTML report.

## 📂 Project Structure
```
WebFUZZ-x-HTB/
├── README.md
├── app.py
└── templates/
    └── index.html
```

- `app.py`: Core Flask application handling enumeration and report generation.
- `templates/index.html`: Web interface with Tailwind CSS and JavaScript for real-time updates.
- `report.html`: Generated report file (created after enumeration).

## ⚠️ Notes
- The current implementation uses simulated enumeration steps (`time.sleep`) for demo purposes. Replace these with actual Nmap, FFUF, and Gobuster commands for production use.
- Debug mode is enabled by default. Disable it (`debug=False`) in production environments.
- Ensure proper permissions for tools like Nmap if running scans that require root access.

## 🌟 Contributing
Got ideas to make WebFUZZ x HTB even better? Fork the repo, submit a pull request, or open an issue! We love contributions that enhance functionality or add new features.

## 📜 License
Licensed under the MIT License. See [LICENSE](LICENSE) for details.

Happy hacking with **WebFUZZ x HTB**! 🎯
