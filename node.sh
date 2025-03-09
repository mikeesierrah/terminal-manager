#!/bin/bash

set -e

# Default values
DEFAULT_NGINX_PORT=80

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root or with sudo privileges."
    exit 1
fi

# Function to prompt for required values
prompt_for_values() {
    read -p "Enter manager node IP address: " MANAGER_IP
    while [[ -z "$MANAGER_IP" ]]; do
        echo "Manager IP address is required."
        read -p "Enter manager node IP address: " MANAGER_IP
    done

    read -p "Enter HTTP port for Nginx [$DEFAULT_NGINX_PORT]: " NGINX_PORT
    NGINX_PORT=${NGINX_PORT:-$DEFAULT_NGINX_PORT}

    read -p "Enter username for authentication: " USERNAME
    while [[ -z "$USERNAME" ]]; do
        echo "Username is required."
        read -p "Enter username for authentication: " USERNAME
    done

    read -s -p "Enter password for authentication: " PASSWORD
    echo
    while [[ -z "$PASSWORD" ]]; do
        echo "Password is required."
        read -s -p "Enter password for authentication: " PASSWORD
        echo
    done
}

# Get required values from user
prompt_for_values

# Installation function
install_packages() {
    echo "Installing required packages..."
    apt update
    apt install -y ttyd nginx nginx-extras
}

# Configure ttyd environment
configure_ttyd() {
    echo "Configuring ttyd environment..."
    sed -i "s|^TTYD_OPTIONS=.*|TTYD_OPTIONS=\"-i lo -O -W -c $USERNAME:$PASSWORD bash\"|" /etc/default/ttyd
}

# Configure Nginx
configure_nginx() {
    echo "Configuring Nginx..."
   
    # Create Nginx configuration file
    cat > /etc/nginx/sites-available/terminal <<EOF
server {
    listen $NGINX_PORT default_server;
    server_name _;
    
    # Hide server information
    server_tokens off;
   
    # IP restriction
    allow $MANAGER_IP;
    deny all;
    
    # Security headers
    more_clear_headers 'Server';
    more_clear_headers 'X-Powered-By';
    more_clear_headers 'X-Real-IP';
    more_clear_headers 'X-Forwarded-For';
    more_clear_headers 'X-Frame-Options';
    
    # WebSocket proxy configuration
    location / {
        proxy_pass http://localhost:7681;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_read_timeout 1800s;
        proxy_send_timeout 1800s;
    }
}
EOF
    # Enable Nginx configuration
    ln -sf /etc/nginx/sites-available/terminal /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
}

# Restart services
restart_services() {
    echo "Restarting services..."
    systemctl restart ttyd
    systemctl enable nginx
    systemctl restart nginx
}

# Main installation process
main() {
    install_packages
    configure_ttyd
    configure_nginx
    restart_services
   
    # Display completion message
    echo "Setup complete!"
    echo "Terminal service is running with authentication"
    echo "Nginx is configured to only allow connections from $MANAGER_IP on port $NGINX_PORT"
   
    # Get local IP address for reference
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    echo "Local IP address: $LOCAL_IP"
    echo "Add this terminal to your manager using: terminal-manager add /node-$(hostname | tr '.' '-') $LOCAL_IP $NGINX_PORT"
}

# Execute main function
main
