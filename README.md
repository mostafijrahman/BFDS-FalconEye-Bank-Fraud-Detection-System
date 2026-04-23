# BFDS FalconEye — Bank Fraud Detection System

![Python](https://img.shields.io/badge/Python-3.9%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0%2B-green)
![SQL Server](https://img.shields.io/badge/SQL%20Server-2016%2B-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive fraud detection platform that combines SQL Server database automation, Flask REST API, and web-based UI for monitoring and investigating suspicious banking transactions.

## 🎯 Project Overview

BFDS FalconEye is a complete fraud detection system that:
- **Detects** suspicious transaction patterns using SQL Server triggers and stored procedures
- **Alerts** investigators to potential fraud through automated rule-based detection
- **Provides** a web interface for real-time monitoring and investigation
- **Secures** access through role-based authentication and authorization

The system consists of three main components:
1. **Database Layer** — SQL Server scripts for tables, triggers, and stored procedures
2. **API Layer** — Flask REST API for data access and authentication
3. **UI Layer** — HTML-based interface for users and investigators

## 📁 Project Structure

```
DataBaseProject/
├── bfds_api/                 # Flask REST API
│   ├── app.py               # Main API application
│   ├── requirements.txt     # Python dependencies
│   ├── .env.example         # Environment configuration template
│   └── README.md            # Detailed API documentation
│
├── bfdsUI/                   # Web Interface
│   ├── login.html           # Authentication page
│   └── app.html             # Main dashboard
│
├── project_script.sql       # Complete database setup (tables, data, triggers, rules)
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

## 📋 Prerequisites

| Tool | Minimum version |
|---|---|
| Python | 3.9+ |
| SQL Server | 2016+ (or Azure SQL) |
| ODBC Driver for SQL Server | 17 or 18 |
| Modern web browser | Chrome, Firefox, Edge |

**Install ODBC Driver:**
- **Windows** — [Microsoft download page](https://learn.microsoft.com/sql/connect/odbc/download-odbc-driver-for-sql-server)
- **Ubuntu/Debian** — `sudo apt-get install -y msodbcsql17`
- **macOS (Homebrew)** — `brew install msodbcsql17`

## 🚀 Quick Start

1. **Database Setup** — Run `project_script.sql` in SSMS to create tables, insert sample data, set up authentication, and configure fraud detection rules

2. **API Setup** — See detailed instructions in `bfds_api/README.md`

3. **Start the API** — `cd bfds_api && python app.py`

4. **Access the UI** — Open `bfdsUI/login.html` in your browser

## 🔍 Fraud Detection Rules

- **Rule 1: Geographic Impossibility** — Detects impossible travel between transactions
- **Rule 2: Structured Transaction Patterns** — Identifies smurfing/structuring attempts
- **Additional Automation** — Merchant blocking, alert generation, structuring detection

## 👥 User Roles

| Role | Permissions |
|------|-------------|
| `super_admin` | Full system access, user management |
| `analyst` | View and investigate alerts, update transactions |
| `compliance` | Create records, update merchant/user data |
| `viewer` | Read-only access to dashboards and reports |

## 📚 Documentation

- **API Documentation:** See `bfds_api/README.md` for detailed API endpoints, setup, and configuration
- **SQL Scripts:** Each script includes inline comments
- **Test Cases:** `TestCaseQuery.sql` for validation

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

Contributions are welcome! Please read our [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 👥 Contributors
Md Mostafijur Rahman - github.com/mostafijrahman - rahmanm74@lsus.edu
Jyotish Batra - github.com/jyotishbatra2003 - batraj71@lsus.edu

