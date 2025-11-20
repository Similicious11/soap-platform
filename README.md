# 🛡️ SOAP Platform
**Security Operations Automation Platform**

A full-stack security automation system that continuously monitors cloud infrastructure for misconfigurations and provides actionable insights through a web dashboard and REST API.

## 🎯 Project Overview

Built as a portfolio project for cybersecurity automation roles, SOAP Platform demonstrates skills in Python automation, Django web development, REST API design, and security operations.

### Key Features

- ✅ **Automated Security Scanning** - Python-based modular scanner
- ✅ **Risk-Based Prioritization** - 0-100 risk scoring algorithm
- ✅ **Real-Time Dashboard** - Professional web interface
- ✅ **REST API** - Full API for tool integration
- ✅ **Database Integration** - SQLite for persistent storage

## 🛠️ Technologies

- **Backend**: Python 3.10, Django 5.2, Django REST Framework
- **Database**: SQLite
- **Frontend**: HTML5, CSS3 (Responsive Design)

## 📊 Scanner Modules

1. **S3 Bucket Security** - Public access, encryption, policies
2. **Security Groups** - Network rules, port exposure
3. **IAM Policies** - Least privilege violations
4. **RDS Databases** - Encryption, public access, backups

## 🚀 Quick Start

### Installation
```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/soap-platform.git
cd soap-platform

# Install dependencies
pip3 install -r requirements.txt

# Initialize database
python3 manage.py migrate --run-syncdb

# Run security scan
python3 cloud_scanner.py

# Start web server
python3 manage.py runserver 0.0.0.0:8000
```

Open browser: `http://localhost:8000`

## 📸 Screenshots

### Dashboard
![Dashboard](docs/dashboard-screenshot.png)

### Findings List
![Findings](docs/findings-screenshot.png)

### Scan History
![Scan History](docs/scan-history-screenshot.png)

## 🔌 API Endpoints

| Endpoint | Description |
|----------|-------------|
| `/api/` | API root |
| `/api/scans/` | List all scans |
| `/api/findings/` | List all findings |
| `/api/stats/` | Dashboard statistics |

## 📈 Results

- **17 Security Findings** detected across 4 categories
- **Risk Scores**: 30-98 based on severity
- **Scan Speed**: < 1 second
- **Categories**: S3, Security Groups, IAM, RDS

## 🎓 Skills Demonstrated

- Security automation and monitoring
- Full-stack web development
- REST API design
- Database modeling
- Risk analysis and prioritization

## 📝 License

MIT License

## 👤 Author

Simran Vaz
- GitHub: [@YOUR_USERNAME](https://github.com/Similicious11)
- LinkedIn: [Your Profile](https://www.linkedin.com/in/simran-vaz/)

---

Built to demonstrate cybersecurity automation capabilities for internship applications.
