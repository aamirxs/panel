#!/bin/bash

# Exit on any error
set -e

# System setup
sudo apt update && sudo apt full-upgrade -y
sudo apt install -y python3-pip python3-venv nginx ufw git

# Create dedicated user
sudo useradd -r -m -d /opt/python-panel -s /bin/bash pythonpanel || echo "User already exists"
sudo mkdir -p /opt/python-panel/{app,venv,projects,logs}
sudo chown -R pythonpanel:pythonpanel /opt/python-panel

# Backup nginx default if exists
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo mv /etc/nginx/sites-enabled/default /etc/nginx/sites-enabled/default.backup
fi

# Firewall configuration
sudo ufw allow OpenSSH
sudo ufw allow 'Nginx Full'
sudo ufw --force enable

# Application setup
sudo -u pythonpanel -i <<'EOF'
cd /opt/python-panel
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip wheel
pip install flask flask-login psutil gunicorn python-dotenv
EOF

# Configure systemd
sudo tee /etc/systemd/system/python-panel.service > /dev/null <<EOL
[Unit]
Description=Python Server Panel
After=network.target

[Service]
User=pythonpanel
Group=pythonpanel
WorkingDirectory=/opt/python-panel/app
Environment="PATH=/opt/python-panel/venv/bin"
ExecStart=/opt/python-panel/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 panel_app:app
Restart=always
RestartSec=5
StandardOutput=append:/opt/python-panel/logs/panel.log
StandardError=append:/opt/python-panel/logs/panel.error.log

[Install]
WantedBy=multi-user.target
EOL

# Configure Nginx with improved security
sudo tee /etc/nginx/sites-available/python-panel > /dev/null <<EOL
server {
    listen 80;
    server_name _;

    # Security headers
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options "SAMEORIGIN";
    add_header X-XSS-Protection "1; mode=block";
    
    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s;
    limit_req zone=one burst=10 nodelay;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        
        # Timeout settings
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    location /static {
        alias /opt/python-panel/app/static;
        expires 7d;
        add_header Cache-Control "public, no-transform";
    }
}
EOL

# Remove default nginx site if exists
sudo rm -f /etc/nginx/sites-enabled/default

# Enable services
sudo systemctl daemon-reload
sudo systemctl enable python-panel.service
sudo systemctl start python-panel.service
sudo ln -s /etc/nginx/sites-available/python-panel /etc/nginx/sites-enabled/
sudo systemctl restart nginx

# Verify nginx config
sudo nginx -t

echo "Installation complete! Please check logs in /opt/python-panel/logs/"