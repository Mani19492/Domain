# 🚀 Deployment Guide

This guide covers various deployment options for the Advanced Domain Reconnaissance Platform.

## 📋 Prerequisites

- Python 3.8+
- Redis Server
- 2GB+ RAM recommended
- SSL certificates (for production)

## 🐳 Docker Deployment (Recommended)

### Quick Start with Docker Compose

```bash
# Clone the repository
git clone https://github.com/yourusername/advanced-domain-recon.git
cd advanced-domain-recon

# Copy environment file
cp .env.example .env

# Edit .env with your API keys
nano .env

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f web
```

### Manual Docker Build

```bash
# Build the image
docker build -t domain-recon:latest .

# Run Redis
docker run -d --name redis redis:7-alpine

# Run the application
docker run -d \
  --name domain-recon \
  --link redis:redis \
  -p 5000:5000 \
  -e REDIS_URL=redis://redis:6379/0 \
  domain-recon:latest
```

## 🖥️ Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Start Redis (macOS with Homebrew)
brew services start redis

# Start Redis (Ubuntu/Debian)
sudo systemctl start redis-server

# Run the application
python app.py
```

## ☁️ Cloud Deployment

### AWS EC2

```bash
# Launch EC2 instance (Ubuntu 20.04 LTS)
# Connect via SSH

# Update system
sudo apt update && sudo apt upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker ubuntu

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Clone and deploy
git clone https://github.com/yourusername/advanced-domain-recon.git
cd advanced-domain-recon
cp .env.example .env
# Edit .env file
docker-compose up -d
```

### Google Cloud Platform

```bash
# Create VM instance
gcloud compute instances create domain-recon \
  --image-family=ubuntu-2004-lts \
  --image-project=ubuntu-os-cloud \
  --machine-type=e2-medium \
  --tags=http-server,https-server

# SSH into instance
gcloud compute ssh domain-recon

# Follow AWS EC2 steps above
```

### DigitalOcean

```bash
# Create droplet via web interface or CLI
doctl compute droplet create domain-recon \
  --image ubuntu-20-04-x64 \
  --size s-2vcpu-2gb \
  --region nyc1

# SSH and follow deployment steps
```

## 🔒 Production Configuration

### SSL/TLS Setup

```bash
# Install Certbot
sudo apt install certbot python3-certbot-nginx

# Get SSL certificate
sudo certbot --nginx -d yourdomain.com

# Auto-renewal
sudo crontab -e
# Add: 0 12 * * * /usr/bin/certbot renew --quiet
```

### Nginx Configuration

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /socket.io/ {
        proxy_pass http://localhost:5000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Environment Variables for Production

```env
# Production settings
FLASK_ENV=production
SECRET_KEY=5e65e067191744249386d16b7d8d7041:4WoflWlx0mDSGN2z:58666568:6591306
DEBUG=False

# Database
DATABASE_URL=postgresql://user:pass@localhost/domain_recon

# Redis
REDIS_URL=redis://localhost:6379/0

# Security
RATE_LIMIT_ENABLED=true
MAX_REQUESTS_PER_MINUTE=5
SESSION_TIMEOUT_MINUTES=30

# API Keys
VITE_VIRUSTOTAL_API_KEY=your_production_key
VITE_WHOISXMLAPI_KEY=your_production_key
VITE_GOOGLE_SAFE_BROWSING_API_KEY=your_production_key
```

## 📊 Monitoring & Logging

### Application Monitoring

```bash
# Install monitoring tools
pip install prometheus-flask-exporter

# Add to app.py
from prometheus_flask_exporter import PrometheusMetrics
metrics = PrometheusMetrics(app)
```

### Log Management

```bash
# Configure log rotation
sudo nano /etc/logrotate.d/domain-recon

# Add:
/app/logs/*.log {
    daily
    missingok
    rotate 52
    compress
    delaycompress
    notifempty
    create 644 www-data www-data
}
```

### Health Checks

```bash
# Add health check endpoint
@app.route('/health')
def health_check():
    return {'status': 'healthy', 'timestamp': datetime.now().isoformat()}
```

## 🔧 Performance Optimization

### Redis Configuration

```bash
# Edit redis.conf
sudo nano /etc/redis/redis.conf

# Optimize settings
maxmemory 1gb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
```

### Gunicorn Configuration

```python
# gunicorn.conf.py
bind = "0.0.0.0:5000"
workers = 4
worker_class = "eventlet"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
timeout = 30
keepalive = 2
```

### Database Optimization

```sql
-- PostgreSQL optimizations
CREATE INDEX idx_monitoring_domain ON monitoring_jobs(domain);
CREATE INDEX idx_scan_history_job_id ON scan_history(job_id);
CREATE INDEX idx_scan_history_scan_time ON scan_history(scan_time);
```

## 🛡️ Security Hardening

### Firewall Configuration

```bash
# UFW setup
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable
```

### Application Security

```python
# Add security headers
from flask_talisman import Talisman

Talisman(app, {
    'force_https': True,
    'strict_transport_security': True,
    'content_security_policy': {
        'default-src': "'self'",
        'script-src': "'self' 'unsafe-inline'",
        'style-src': "'self' 'unsafe-inline'"
    }
})
```

## 📈 Scaling

### Horizontal Scaling

```yaml
# docker-compose.scale.yml
version: '3.8'
services:
  web:
    build: .
    ports:
      - "5000-5003:5000"
    deploy:
      replicas: 4
  
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf
```

### Load Balancer Configuration

```nginx
upstream domain_recon {
    server localhost:5000;
    server localhost:5001;
    server localhost:5002;
    server localhost:5003;
}

server {
    listen 80;
    location / {
        proxy_pass http://domain_recon;
    }
}
```

## 🔄 Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh
DATE=$(date +%Y%m%d_%H%M%S)
pg_dump domain_recon > /backups/domain_recon_$DATE.sql
find /backups -name "domain_recon_*.sql" -mtime +7 -delete
```

### Application Backup

```bash
#!/bin/bash
# Full application backup
tar -czf /backups/app_$(date +%Y%m%d).tar.gz \
  /app \
  --exclude=/app/logs \
  --exclude=/app/__pycache__ \
  --exclude=/app/.git
```

## 🚨 Troubleshooting

### Common Issues

1. **Redis Connection Error**
   ```bash
   # Check Redis status
   redis-cli ping
   # Should return PONG
   ```

2. **Port Already in Use**
   ```bash
   # Find process using port 5000
   sudo lsof -i :5000
   # Kill process
   sudo kill -9 <PID>
   ```

3. **Permission Denied**
   ```bash
   # Fix file permissions
   sudo chown -R www-data:www-data /app
   sudo chmod -R 755 /app
   ```

### Log Analysis

```bash
# View application logs
docker-compose logs -f web

# View Redis logs
docker-compose logs -f redis

# View system logs
sudo journalctl -u domain-recon -f
```

## 📞 Support

For deployment issues:
- Check the [Issues](https://github.com/yourusername/advanced-domain-recon/issues) page
- Join our [Discord](https://discord.gg/domain-recon) community
- Email: support@advanced-domain-recon.com

---

**🚀 Happy Deploying!**