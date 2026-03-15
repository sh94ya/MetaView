![Supported Python versions](https://img.shields.io/badge/python-3.8+-blue.svg)
![Supported Python versions](https://img.shields.io/badge/python-3.13+-blue.svg)
![Vue3](https://img.shields.io/badge/vue-3+-3eaf7c.svg?style=flat-square&logo=vue.js)
![Vue3 UI](https://img.shields.io/badge/vue3-UI-ff69b4.svg?style=flat-square&logo=vue.js)
![MIT](https://img.shields.io/badge/license-MIT-ccc.svg?style=flat-square&logo=reliance-industries-limited)

<p align="center">
        <img alt="Static" src="https://github.com/sh94ya/MetaView/blob/main/workspace/view/icons/favicon/favicon-128x128.png?raw=true">
</p>

## <div align="center">MetaView</br>Metasploit Framework Web UI on Vue3</div>
<div align="center">A web-based interface for the Metasploit Framework with multi-user support and an intuitive UI.</div>

## ✨ Capabilities
- Modern web interface
- Visualization of data stored in the Metasploit Framework database
- Import data from **MaxPatrol**, **Nmap**, **Acunetix**
- View the structure of websites being tested
![MainView](https://raw.githubusercontent.com/sh94ya/MetaView/assets/main1.png)

## 👥 Team mode
- Separation of roles and projects
- Tag operation history
- Creating tasks for project users

## 📊 Dashboards
- Live dashboards with metrics
- Visualization of scan results
  ![Dashboards](https://raw.githubusercontent.com/sh94ya/MetaView/assets/dashboards.png)

## 🚀 Quick start
Local installation (requires **Python 3.8 - 3.13**)
```bash
# Clone
git clone https://github.com/sh94ya/MetaView.git
cd MetaView

#Linux
python3 -m venv venv
source venv/bin/activate
pip install -e .
python3 main.py

#Windows
python.exe -m venv venv
venv\Scripts\activate.bat
pip install -e .
python.exe main.py

# Open in a browser (default creds - admin:admin)
http://localhost:5000
```

## 🔧 Configuration
Edit config.ini:

### Metasploit DB
Connect to the PostgreSQL Database
```
login=msf
password=msf
address=127.0.0.1
port=5432
db=msf
```

### Security
Change your secret key:
```
secret_key = 'change-your-secret_key'
```

## 🛠 Тechnology stack
Flask + Vue 3 (with Quasar Framework)

## ⚠️ Disclaimer
IMPORTANT: This tool is intended solely for:
- Legal penetration testing
- Educational purposes
- Cybersecurity research

**The developer is not responsible for illegal use.**

## 📄 License
Distributed under the MIT License. See the [LICENSE](https://github.com/sh94ya/MetaView?tab=MIT-1-ov-file) file for details.

## 👨‍💻 Author
sh94ya — Lead Developer — GitHub

## 🌟 Support the project
Give a ⭐️ on GitHub if you like the project!
