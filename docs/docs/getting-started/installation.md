---
sidebar_position: 1
title: Installation Guide
---

# Installation Guide

The SCCAP is designed for local setup and deployment using Docker and Docker Compose. This guide will walk you through the process.

## Prerequisites

Before you begin, ensure you have the following installed and configured on your system:

* **Docker Engine**: Make sure Docker is installed and the Docker daemon is running.
    * *Download*: [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose for Mac and Windows).
* **Docker Compose**:
    * Usually included with Docker Desktop.
    * For Linux, if it's not included or you need a specific version, follow the [official Docker Compose installation guide](https://docs.docker.com/compose/install/).
* **Git**: Required for cloning the project repository.
    * *Download*: [Git](https://git-scm.com/downloads).
* **Code Editor**: A code editor like VS Code, Sublime Text, or others for viewing and editing configuration files.
* **(Optional for specific host commands) Python & Poetry**: If you plan to run backend commands (like Alembic migrations) directly on your host machine instead of inside Docker (not recommended for initial setup), you'll need Python (version 3.12+) and Poetry installed.


## Quick Start (Recommended)

The easiest way to get started is by using the automated setup script. This script handles prerequisite checks, environment configuration (generating secure keys), Docker build, database initialization, and UI dependency installation.

### macOS / Linux

1.  **Clone the Repository**:
    ```bash
    git clone https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform.git
    cd ai-secure-coding-compliance-platform
    ```

2.  **Run the Interactive Setup Script**:
    ```bash
    chmod +x setup.sh
    ./setup.sh
    ```
    *   The setup script is fully interactive with backward travel options. It will guide you through:
        *   Checking prerequisites.
        *   Prompting for your Domain or IP.
        *   Allowing you to automatically provision Let's Encrypt SSL via a specialized container.
        *   Handling initial Docker and database setup.

### Windows

1.  **Clone the Repository**:
    ```powershell
    git clone https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform.git
    cd ai-secure-coding-compliance-platform
    ```

2.  **Run the Interactive Setup Script**:
    Double-click `setup.bat` or run it from the command line:
    ```cmd
    setup.bat
    ```
    *   Like the bash script, the Windows setup handles configuration interactively with validations and backward navigation, before initializing Docker and the database.

Once the script completes, you will see a dynamic "Setup Complete!" message with the correct HTTP/HTTPS URLs for the application and Grafana depending on your choices.

!!! tip "First user becomes superuser"

    The first account you register on the running app becomes the
    platform's superuser and is routed through `/setup` to finish LLM,
    SMTP, and system configuration before the rest of the UI unlocks.

---

## Cloud Deployment / Linux VPS (Fresh Install)

If you are deploying to a fresh Linux virtual machine (e.g., AWS EC2, DigitalOcean Droplet, Google Compute Engine) running Ubuntu or Debian, follow these comprehensive steps to prepare the system and install the platform.

### 1. Update System Packages
Ensure your system is up to date:
```bash
sudo apt update && sudo apt upgrade -y
```

### 2. Install Dependencies (Git, Python, Node.js)
The setup script requires Git (to clone), Python 3 (to generate secure secrets), and Node.js (to install frontend dependencies).
```bash
sudo apt install -y git python3 python3-venv curl
# Install Node.js (LTS version recommended)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 3. Install Docker & Docker Compose
We recommend using the official Docker installation script for the latest version.
```bash
# Download and run the Docker installation script
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add your current user to the 'docker' group (avoids using sudo for docker commands)
sudo usermod -aG docker $USER

# Apply group changes immediately
newgrp docker
```

### 4. Clone and Install
Now that all dependencies are ready, clone the repository and run the setup script.

```bash
git clone https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform.git
cd ai-secure-coding-compliance-platform
chmod +x setup.sh
./setup.sh
```

---

## Troubleshooting: Low RAM VPS (Build Failures)

If your installation fails with a `Killed` message or the connection drops during the build process, your server likely ran out of RAM. This is common on instances with less than 4GB of RAM (e.g., typical 1GB/2GB Droplets or EC2 micro instances).

**Solution: Add Swap Space**

Run the following commands to create a 4GB swap file, which effectively extends your RAM using disk space:

```bash
# 1. Allocate a 4GB file for swap
sudo fallocate -l 4G /swapfile

# 2. Secure the file permissions
sudo chmod 600 /swapfile

# 3. Mark the file as swap space
sudo mkswap /swapfile

# 4. Enable the swap
sudo swapon /swapfile

# 5. Make it permanent (persist after reboot)
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

# 6. Verify swap is active
sudo swapon --show
```

After adding swap, try running `./setup.sh` again.

---

## Troubleshooting: "No space left on device" (Disk Full)

If your build fails with disk space errors despite having plenty of free space on your server, the issue is likely **build-time artifacts**. Docker caches every step of the build process, and large dependencies (like machine learning libraries) can quickly fill up the disk with intermediate layers, even if the final running application is small.

**Solution: Prune Docker Data**

1.  **Stop all running containers:**
    ```bash
    docker compose down
    ```

2.  **Prune the Docker system:**
    This removes all stopped containers, unused networks, and **build cache** (which is usually the culprit).
    ```bash
    docker system prune -a
    ```
    *Type `y` when prompted.*

3.  **Retry the setup:**
    ```bash
    ./setup.sh
    ```

---

## Manual Installation Steps


1.  **Clone the Repository**:
    Open your terminal and clone the SCCAP repository:
    ```bash
    git clone https://github.com/nerdy-krishna/ai-secure-coding-compliance-platform.git
    cd ai-secure-coding-compliance-platform
    ```

2.  **Create and Configure the Environment File (`.env`)**:
    The platform uses a `.env` file in the project root for infrastructure configuration only — LLM provider credentials live in the database and are entered through the `/setup` wizard or the Admin → LLM Configurations page.
    * Copy the example environment file to a new `.env` file:
        ```bash
        cp .env.example .env
        ```
        If `.env.example` is not available (it should be committed to your repository), you'll need to create `.env` manually based on the requirements below.
    * **Edit the `.env` file** with your preferred text editor. Pay close attention to the following critical variables:
        * `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB`: Credentials for the PostgreSQL database.
        * `RABBITMQ_DEFAULT_USER`, `RABBITMQ_DEFAULT_PASS`: Credentials for RabbitMQ.
        * `SECRET_KEY`: **Crucial for security.** Generate a strong, unique random string (e.g., using a password manager or the command `openssl rand -hex 32`).
        * `ENCRYPTION_KEY`: **Also crucial.** Fernet key used to encrypt LLM API keys, SMTP passwords, and other secrets at rest. Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
        * `APP_PORT`: The port on your host machine that will map to the backend application (default is usually `8000`).
        * `ALLOWED_ORIGINS`: A comma-separated list of origins allowed for CORS (e.g., `http://localhost:5173` for the default frontend development server).
        * `LITELLM_LOCAL_MODEL_COST_MAP=True`: recommended. Pins LiteLLM's token-counting / cost-estimation against the bundled price map so runtime scan cost calculations don't make network calls.
    * LLM provider API keys are **not** stored as env vars — admins enter them per-model at Setup or under Admin → LLM Configurations; they're Fernet-encrypted in the `llm_configurations` table using `ENCRYPTION_KEY`.
    * For a detailed explanation of all environment variables, please refer to the [**Configuration**](./configuration.md) page.

3.  **Build and Run Services with Docker Compose**:
    From the project root directory (`ai-secure-coding-compliance-platform`), execute the following command:
    ```bash
    docker compose up --build -d
    ```
    This command will:
    * `--build`: Build the Docker image for the application and worker services as defined in the `Dockerfile` (if they haven't been built before or if the `Dockerfile` has changed).
    * Pull the official images for PostgreSQL, RabbitMQ, and Qdrant if they are not already present locally.
    * Create and start all services (application, worker, database, message queue, vector database) in detached mode (`-d`), meaning they will run in the background.
    * The initial build process might take a few minutes depending on your internet connection and system resources.

4.  **Initialize the Database Schema (First-Time Setup)**:
    Once the services are running (especially the `db` service), you need to apply the database migrations to set up the necessary tables. The recommended way to do this is by executing the command within the running application container:
    ```bash
    docker compose exec app poetry run alembic upgrade head
    ```
    This ensures the migration runs in the correct environment with all dependencies.
    * Wait for the `db` container to be healthy before running this. You can check its status with `docker compose ps`.
    * If this command fails, check the logs using `docker compose logs app` and `docker compose logs db`.

## Verifying the Installation

After completing the steps above, you can verify that the platform is running correctly:

1.  **Check Docker Containers**:
    Run `docker compose ps`. All services (`app`, `worker`, `db`, `rabbitmq`, `vector_db`, `fluentd`, `loki`, `grafana`, `ui`) should have a status of `Up` or `healthy`.

2.  **Access the Backend API**:
    * The FastAPI backend should be available at `http://localhost:<APP_PORT>` (e.g., `http://localhost:8000` if `APP_PORT=8000` in your `.env`).
    * You can access the API documentation (Swagger UI) at `http://localhost:<APP_PORT>/docs` (e.g., `http://localhost:8000/docs`). This page should load and show the available API endpoints.

3.  **Access the Frontend Application**:
    * The React frontend (served by Vite) will be available on its configured port, typically `http://localhost:5173` (check your `secure-code-ui` setup if you changed the port).

4.  **Check RabbitMQ Management UI**:
    * You can monitor RabbitMQ queues and exchanges via its management interface at `http://localhost:<RABBITMQ_MANAGEMENT_PORT>` (e.g., `http://localhost:15672`, using the RabbitMQ credentials from your `.env` file).

## Stopping the Platform Services

To stop all running services defined in `docker-compose.yml`:
```bash
docker compose down
```
This command stops and removes the containers. Your data stored in Docker volumes (like PostgreSQL data) will persist unless you explicitly remove the volumes.

## Updating the Platform

To update to the latest version of the platform:
1.  Navigate to the project root: `cd ai-secure-coding-compliance-platform`
2.  Pull the latest changes from the Git repository: `git pull origin main` (or the relevant branch)
3.  Rebuild the images if there have been changes to `Dockerfile` or application dependencies: `docker compose up --build -d`
4.  Apply any new database migrations: `docker compose exec app poetry run alembic upgrade head`

## Troubleshooting Common Issues

* **Port Conflicts**: If a service fails to start due to a port already being in use, you can change the host-side port mapping in your `.env` file (e.g., change `APP_PORT` or `RABBITMQ_PORT`) and then restart the services with `docker compose up -d`.
* **Docker Daemon Not Running**: Ensure the Docker service/daemon is running on your system.
* **Insufficient Resources**: Docker might require a certain amount of RAM/CPU. If services are crashing, check Docker's resource allocation settings.
* **Build Failures**: If `docker compose build` fails, check the output for specific errors. It could be network issues preventing dependency downloads or errors in the `Dockerfile`.
* **Service Connection Issues** (e.g., `app` can't connect to `db`):
    * Double-check your `.env` file for correct hostnames (usually the service names like `db`, `rabbitmq`), usernames, passwords, and database names.
    * Examine the logs for the affected services: `docker compose logs app`, `docker compose logs db`, `docker compose logs worker`.
* **Alembic Errors**: Ensure the `db` service is fully up and healthy before running `alembic upgrade head`. `alembic/env.py` drives migrations through `create_async_engine()`, so `ALEMBIC_DATABASE_URL` must use the asyncpg driver (`postgresql+asyncpg://…`) even though Alembic's own CLI is sync.