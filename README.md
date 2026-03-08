# NHI Map

Non-Human Identity inventory tool for AWS and Azure. Crawls cloud environments to discover service accounts, service principals, managed identities, access keys, OIDC/SAML providers, and more.

Built with FastAPI, PostgreSQL, and a single-page dark-theme frontend.

## What it does

- Discovers IAM roles, service account users, instance profiles, OIDC providers, SAML providers (AWS)
- Discovers service principals, app registrations, managed identities, federated credentials (Azure)
- Tracks credentials (access keys, password credentials, certificates) with expiration dates
- Risk scoring based on key age, rotation, unused credentials, privileged role assignments
- 7-day trend chart, diff between crawl dates, CSV export

## Prerequisites

### AWS CLI

Install and authenticate before running NHI Map. The crawler shells out to `aws` CLI commands.

```bash
# Install
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip && sudo ./aws/install

# Authenticate
aws configure
# or
aws sso login --profile your-profile
```

Verify: `aws sts get-caller-identity` should return your account info.

### Azure CLI

Install and authenticate. The crawler shells out to `az` CLI commands.

```bash
# Install
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Authenticate
az login
```

Verify: `az account show` should return your subscription info.

### Python 3.10+

```bash
sudo apt install python3 python3-pip python3-venv
```

### PostgreSQL

```bash
sudo apt install postgresql postgresql-contrib
```

## Setup

Run the setup script to create the database, user, and install Python dependencies:

```bash
chmod +x setup.sh
./setup.sh
```

### Default database credentials

The app ships with default credentials for local development:

| Setting | Default |
|---------|---------|
| DB User | `nhi_user` |
| DB Password | `changeme` |
| Database | `nhi_map` |
| API Key | `changeme-generate-a-real-key` (auth disabled when default) |

**Change these before exposing to any network.** Edit `.env` in the `backend/` directory:

```bash
cp backend/.env.example backend/.env
# Edit backend/.env with real values
```

## Run

### Manual

```bash
cd backend
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000
```

Open `http://localhost:8000`

### As a systemd service

```bash
sudo cp nhi-map.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nhi-map
sudo systemctl start nhi-map
```

Check status: `sudo systemctl status nhi-map`

View logs: `sudo journalctl -u nhi-map -f`

## Project structure

```
backend/
  main.py          - FastAPI app, all API endpoints
  models.py        - SQLAlchemy models (Account, Identity, Credential, CrawlRun)
  database.py      - DB engine and session
  config.py        - Settings (reads from .env)
  crawlers/
    aws_crawler.py   - AWS IAM crawling
    azure_crawler.py - Azure AD crawling
frontend/
  index.html       - Single-page UI
  logo.png         - App icon
```
