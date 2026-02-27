# Bad Dockerfile — ContractGuard sample
# Contains multiple security anti-patterns

FROM ubuntu:latest

# Running as root (no USER directive)
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    wget \
    sudo \
    openssh-server

# Hardcoded secrets in ENV
ENV DB_PASSWORD=admin123
ENV API_KEY=DEMO_FAKE_API_KEY_NOT_A_REAL_SECRET_00000000000
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# COPY everything including .git, .env, etc.
COPY . /app

WORKDIR /app

# Install from piped curl (supply chain risk)
RUN curl -sSL https://example.com/install.sh | bash

# Too many RUN layers
RUN pip3 install flask
RUN pip3 install requests
RUN pip3 install sqlalchemy
RUN pip3 install celery
RUN pip3 install redis
RUN pip3 install gunicorn

# Using sudo
RUN sudo chmod 777 /app

# Exposing SSH port
EXPOSE 22
EXPOSE 8080

CMD ["python3", "app.py"]
