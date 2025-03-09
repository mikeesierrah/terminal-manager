#!/bin/bash

set -e

# Default values
DEFAULT_CONFIG_DIR="/etc/terminal-manager"
DEFAULT_NGINX_DIR="/etc/nginx"

if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root or with sudo privileges."
    exit 1
fi

prompt_for_domain() {
    read -p "Enter domain name for the terminal manager: " DOMAIN
    while [[ -z "$DOMAIN" ]]; do
        echo "Domain name is required."
        read -p "Enter domain name for the terminal manager: " DOMAIN
    done
}

prompt_for_domain
CONFIG_DIR=$DEFAULT_CONFIG_DIR
NGINX_DIR=$DEFAULT_NGINX_DIR

install_packages() {
    echo "Installing required packages..."
    apt update
    apt install -y nginx certbot python3-certbot-nginx jq
}

setup_config_dir() {
    echo "Setting up configuration directory..."
    mkdir -p $CONFIG_DIR
    chmod 700 $CONFIG_DIR

    # Create initial configuration file
    CONFIG_FILE="$CONFIG_DIR/terminals.json"
    if [[ ! -f "$CONFIG_FILE" ]]; then
        echo '{"terminals": []}' >"$CONFIG_FILE"
        chmod 600 "$CONFIG_FILE"
    fi
}

create_nginx_template() {
    echo "Creating Nginx configuration templates..."

    # Create HTTP-only template for initial setup
    NGINX_HTTP_TEMPLATE="$CONFIG_DIR/nginx-http-template.conf"
    cat >"$NGINX_HTTP_TEMPLATE" <<EOF
server {
    listen 80;
    server_name {{DOMAIN}};
    
    # Server information
    server_tokens off;
    
    # Root directory for web content
    root /var/www/html;
    index index.html;
    
    # Main page
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

    # Create full HTTPS template for after certificate acquisition
    NGINX_TEMPLATE="$CONFIG_DIR/nginx-template.conf"
    cat >"$NGINX_TEMPLATE" <<EOF
server {
    listen 80;
    server_name {{DOMAIN}};
    
    # Redirect all HTTP traffic to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name {{DOMAIN}};
    
    # SSL configuration
    ssl_certificate /etc/letsencrypt/live/{{DOMAIN}}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{{DOMAIN}}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384';
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-XSS-Protection "1; mode=block";
    add_header Referrer-Policy no-referrer;
    
    # Server information
    server_tokens off;
    
    # Root directory for web content
    root /var/www/html;
    index index.html;
    
    # Main page
    location = / {
        try_files \$uri \$uri/ =404;
    }
    
    # Terminal locations will be included below
    {{TERMINAL_LOCATIONS}}
}
EOF
}

# Create terminal-manager utility
create_utility_script() {
    echo "Creating management utility..."
    UTILITY_SCRIPT="/usr/local/bin/terminal-manager"
    cat >"$UTILITY_SCRIPT" <<EOF
#!/bin/bash

CONFIG_DIR="$CONFIG_DIR"
CONFIG_FILE="\$CONFIG_DIR/terminals.json"
NGINX_TEMPLATE="\$CONFIG_DIR/nginx-template.conf"
NGINX_CONF="$NGINX_DIR/sites-available/$DOMAIN"
DOMAIN="$DOMAIN"

# Check if running as root
if [[ \$EUID -ne 0 ]]; then
    echo "This script must be run as root or with sudo privileges."
    exit 1
fi

# Function to display help
show_help() {
    echo "Usage: \$0 COMMAND [OPTIONS]"
    echo "Manages terminal node configurations."
    echo
    echo "Commands:"
    echo "  list                    List all configured terminals"
    echo "  add NODE IP PORT        Add a new terminal or update existing one"
    echo "  remove NODE             Remove a terminal configuration"
    echo "  reload                  Reload Nginx configuration"
    echo "  help                    Display this help message"
    echo
    echo "Examples:"
    echo "  \$0 add /node-dev 192.168.1.101 80"
    echo "  \$0 remove /node-dev"
    echo "  \$0 list"
    exit 0
}

# Function to update Nginx configuration
update_nginx_config() {
    # Generate location blocks from JSON configuration
    LOCATIONS=""
    
    TERMINALS=\$(jq -r '.terminals[] | "\(.path) \(.ip) \(.port)"' "\$CONFIG_FILE")
    
    while read -r NODE IP PORT; do
        if [[ -n "\$NODE" && -n "\$IP" && -n "\$PORT" ]]; then
            LOCATION="\\n    location \$NODE/ {\\n"
            LOCATION+="\        proxy_pass http://\$IP:\$PORT/;\\n"
            LOCATION+="\        proxy_http_version 1.1;\\n"
            LOCATION+="\        proxy_set_header Upgrade \\\$http_upgrade;\\n"
            LOCATION+="\        proxy_set_header Connection \"upgrade\";\\n"
            LOCATION+="\        proxy_set_header Host \\\$host;\\n"
            LOCATION+="\        proxy_set_header X-Real-IP \\\$remote_addr;\\n"
            LOCATION+="\        proxy_read_timeout 1800s;\\n"
            LOCATION+="\        proxy_send_timeout 1800s;\\n"
            LOCATION+="\    }\\n"
            
            LOCATIONS+="\$LOCATION"
        fi
    done <<< "\$TERMINALS"
    
    # Generate Nginx configuration from template
    sed -e "s|{{DOMAIN}}|\$DOMAIN|g" -e "s|{{TERMINAL_LOCATIONS}}|\$LOCATIONS|g" "\$NGINX_TEMPLATE" > "\$NGINX_CONF"
    
    # Test and reload Nginx configuration
    nginx -t && systemctl reload nginx
    return \$?
}

# Process commands
case "\$1" in
    list)
        echo "Configured terminals:"
        jq -r '.terminals[] | "[\(.path)] => \(.ip):\(.port)"' "\$CONFIG_FILE"
        ;;
        
    add)
        if [[ -z "\$2" || -z "\$3" || -z "\$4" ]]; then
            echo "Error: Missing parameters for add command."
            echo "Usage: \$0 add NODE IP PORT"
            exit 1
        fi
        
        PATH_VALUE="\$2"
        IP_VALUE="\$3"
        PORT_VALUE="\$4"
        
        # Format path properly
        PATH_VALUE=\${PATH_VALUE#/}
        PATH_VALUE="/\$PATH_VALUE"
        
        # Check if path already exists
        EXISTS=\$(jq -r ".terminals[] | select(.path == \"\$PATH_VALUE\") | .path" "\$CONFIG_FILE")
        
        if [[ -n "\$EXISTS" ]]; then
            # Update existing terminal
            jq ".terminals = [.terminals[] | if .path == \"\$PATH_VALUE\" then {path: \"\$PATH_VALUE\", ip: \"\$IP_VALUE\", port: \"\$PORT_VALUE\"} else . end]" "\$CONFIG_FILE" > "\$CONFIG_FILE.tmp"
            mv "\$CONFIG_FILE.tmp" "\$CONFIG_FILE"
            echo "Updated terminal configuration for \$PATH_VALUE"
        else
            # Add new terminal
            jq ".terminals += [{path: \"\$PATH_VALUE\", ip: \"\$IP_VALUE\", port: \"\$PORT_VALUE\"}]" "\$CONFIG_FILE" > "\$CONFIG_FILE.tmp"
            mv "\$CONFIG_FILE.tmp" "\$CONFIG_FILE"
            echo "Added new terminal configuration for \$PATH_VALUE"
        fi
        
        # Update Nginx configuration
        if update_nginx_config; then
            echo "Configuration updated and applied successfully."
        else
            echo "Error: Failed to update configuration."
            exit 1
        fi
        ;;
        
    remove)
        if [[ -z "\$2" ]]; then
            echo "Error: Missing parameter for remove command."
            echo "Usage: \$0 remove NODE"
            exit 1
        fi
        
        PATH_VALUE="\$2"
        
        # Format path properly
        PATH_VALUE=\${PATH_VALUE#/}
        PATH_VALUE="/\$PATH_VALUE"
        
        # Check if path exists
        EXISTS=\$(jq -r ".terminals[] | select(.path == \"\$PATH_VALUE\") | .path" "\$CONFIG_FILE")
        
        if [[ -n "\$EXISTS" ]]; then
            # Remove terminal
            jq ".terminals = [.terminals[] | select(.path != \"\$PATH_VALUE\")]" "\$CONFIG_FILE" > "\$CONFIG_FILE.tmp"
            mv "\$CONFIG_FILE.tmp" "\$CONFIG_FILE"
            echo "Removed terminal configuration for \$PATH_VALUE"
            
            # Update Nginx configuration
            if update_nginx_config; then
                echo "Configuration updated and applied successfully."
            else
                echo "Error: Failed to update configuration."
                exit 1
            fi
        else
            echo "Error: Terminal configuration for \$PATH_VALUE not found."
            exit 1
        fi
        ;;
        
    reload)
        # Update Nginx configuration
        if update_nginx_config; then
            echo "Configuration updated and applied successfully."
        else
            echo "Error: Failed to update configuration."
            exit 1
        fi
        ;;
        
    help|*)
        show_help
        ;;
esac
EOF

    # Make utility script executable
    chmod +x "$UTILITY_SCRIPT"
}

# Create web interface
create_web_interface() {
    echo "Creating web interface..."
    mkdir -p /var/www/html
    mkdir -p /var/www/html/assets
    wget -O /var/www/html/index.html https://raw.githubusercontent.com/mikeesierrah/terminal-manager/refs/heads/main/index.html
    wget -O /var/www/html/assets/index.css https://raw.githubusercontent.com/mikeesierrah/terminal-manager/refs/heads/main/assets/index.css
    wget -O /var/www/html/assets/index.js https://raw.githubusercontent.com/mikeesierrah/terminal-manager/refs/heads/main/assets/index.js
}

# Set up Nginx and SSL
setup_nginx_ssl() {
    echo "Setting up Nginx..."

    # Step 1: Create initial HTTP-only Nginx configuration
    NGINX_CONF="$NGINX_DIR/sites-available/$DOMAIN"
    sed -e "s|{{DOMAIN}}|$DOMAIN|g" "$CONFIG_DIR/nginx-http-template.conf" >"$NGINX_CONF"

    ln -sf "$NGINX_CONF" "$NGINX_DIR/sites-enabled/"

    rm -f "$NGINX_DIR/sites-enabled/default"

    systemctl reload nginx

    echo "Obtaining SSL certificate..."
    certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email

    echo "Updating to HTTPS configuration..."
    sed -e "s|{{DOMAIN}}|$DOMAIN|g" -e "s|{{TERMINAL_LOCATIONS}}||g" "$CONFIG_DIR/nginx-template.conf" >"$NGINX_CONF"

    systemctl reload nginx
}

# Main installation process
main() {
    install_packages
    setup_config_dir
    create_nginx_template
    create_utility_script
    create_web_interface
    setup_nginx_ssl

    # Display completion message
    echo "Setup complete!"
    echo "Terminal manager is now set up at https://$DOMAIN"
    echo
    echo "Management commands:"
    echo "  sudo terminal-manager add /node-name 192.168.1.101 80    # Add or update a terminal"
    echo "  sudo terminal-manager remove /node-name                  # Remove a terminal"
    echo "  sudo terminal-manager list                               # List all terminals"
    echo "  sudo terminal-manager reload                             # Reload configuration"
}

# Execute main function
main
