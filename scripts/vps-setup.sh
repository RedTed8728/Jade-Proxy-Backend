#!/bin/bash
set -e

JADE_DIR="/opt/jade"
REPO_URL="https://github.com/YOUR_USERNAME/jade.git"

echo "=== jade vps setup ==="

apt-get update
apt-get install -y git curl nodejs npm docker.io docker-compose nginx certbot python3-certbot-nginx

mkdir -p /etc/systemd/resolved.conf.d/
cat > /etc/systemd/resolved.conf.d/dns-over-tls.conf <<EOF
[Resolve]
DNS=1.1.1.1 1.0.0.1
DNSOverTLS=yes
FallbackDNS=8.8.8.8 8.8.4.4
EOF

systemctl restart systemd-resolved

rm -rf $JADE_DIR
git clone $REPO_URL $JADE_DIR
cd $JADE_DIR

if [ ! -f .env ]; then
    echo "JADE_KEY=$(openssl rand -hex 32)" > .env
fi

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw --force enable

docker-compose up -d

echo "=== jade deployed ==="
echo "run: certbot --nginx -d yourdomain.com"
echo "jade on port 8080"