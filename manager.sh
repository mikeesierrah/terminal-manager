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

install_telegram_bot() {
    echo "Installing dependencies..."

    apt install -y python3 python3-pip python3-venv

    mkdir -p /opt/terminal-manager-bot
    cd /opt/terminal-manager-bot || exit

    python3 -m venv venv
    source venv/bin/activate

    pip install --upgrade pip
    pip install python-telegram-bot

    echo "Dependencies installed."

    read -p "Enter Telegram Bot Token: " BOT_TOKEN
    read -p "Enter Admin Telegram User IDs (space-separated): " ADMIN_IDS

    # Convert space-separated admin IDs into a Python list format
    FORMATTED_ADMIN_IDS=$(echo "$ADMIN_IDS" | sed 's/ /, /g')

    BOT_SCRIPT="/opt/terminal-manager-bot/bot.py"
    cat >"$BOT_SCRIPT" <<EOF
#!/usr/bin/env python3

import os
import json
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, CallbackContext

TOKEN = "$BOT_TOKEN"
ADMIN_IDS = [$FORMATTED_ADMIN_IDS]  # Convert input to a list
DOMAIN = "$DOMAIN"  # The domain input by the user

logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

def is_admin(user_id):
    return user_id in ADMIN_IDS

async def start(update: Update, context: CallbackContext) -> None:
    if is_admin(update.effective_user.id):
        await update.message.reply_text("Welcome, Admin.")
    else:
        await update.message.reply_text("You are not authorized to use this bot.")

async def help(update: Update, context: CallbackContext) -> None:
    help_text = """
    Available Commands:
    /start - Start the bot
    /help - Show this help message
    /list - List all configured terminals
    /add NODE IP PORT - Add or update a terminal
    /remove NODE - Remove a terminal
    """
    await update.message.reply_text(help_text)

async def list_terminals(update: Update, context: CallbackContext) -> None:
    if not is_admin(update.effective_user.id):
        return

    config_file = "/etc/terminal-manager/terminals.json"
    if not os.path.exists(config_file):
        await update.message.reply_text("No terminals configured.")
        return

    with open(config_file, "r") as file:
        data = json.load(file)
        terminals = data.get("terminals", [])

    if not terminals:
        await update.message.reply_text("No terminals configured.")
        return

    response_lines = ["*Configured Terminals:*", ""]
    for idx, term in enumerate(terminals, start=1):
        node = term["path"].lstrip('/')
        full_url = f"{DOMAIN.rstrip('/')}/{node}"
        response_lines.append(f"*{idx}. {full_url}*")
        response_lines.append(f"   _IP:_ {term['ip']}")
        response_lines.append(f"   _Port:_ {term['port']}\n")

    response = "\n".join(response_lines)
    await update.message.reply_text(response, parse_mode="Markdown")

async def add_terminal(update: Update, context: CallbackContext) -> None:
    if not is_admin(update.effective_user.id):
        return

    if len(context.args) < 3:
        await update.message.reply_text("Usage: /add NODE IP PORT")
        return

    path, ip, port = context.args
    path = f"/{path.lstrip('/')}"
    config_file = "/etc/terminal-manager/terminals.json"

    terminals = []
    if os.path.exists(config_file):
        with open(config_file, "r") as file:
            terminals = json.load(file).get("terminals", [])

    for term in terminals:
        if term["path"] == path:
            term.update({"ip": ip, "port": port})
            break
    else:
        terminals.append({"path": path, "ip": ip, "port": port})

    with open(config_file, "w") as file:
        json.dump({"terminals": terminals}, file, indent=4)

    await update.message.reply_text(f"Added/Updated terminal: {path}")

async def remove_terminal(update: Update, context: CallbackContext) -> None:
    if not is_admin(update.effective_user.id):
        return

    if len(context.args) < 1:
        await update.message.reply_text("Usage: /remove NODE")
        return

    path = f"/{context.args[0].lstrip('/')}"
    config_file = "/etc/terminal-manager/terminals.json"

    if not os.path.exists(config_file):
        await update.message.reply_text("No terminals configured.")
        return

    with open(config_file, "r") as file:
        data = json.load(file)

    terminals = [t for t in data.get("terminals", []) if t["path"] != path]

    with open(config_file, "w") as file:
        json.dump({"terminals": terminals}, file, indent=4)

    await update.message.reply_text(f"Removed terminal: {path}")

def main():
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help))  # Add the help command
    app.add_handler(CommandHandler("list", list_terminals))
    app.add_handler(CommandHandler("add", add_terminal))
    app.add_handler(CommandHandler("remove", remove_terminal))

    app.run_polling()

if __name__ == "__main__":
    main()
EOF

    chmod +x "$BOT_SCRIPT"
    echo "Bot script installed at /opt/terminal-manager-bot/bot.py."

    # Create systemd service for auto-start
    SYSTEMD_SERVICE="/etc/systemd/system/terminal-manager-bot.service"
    cat >"$SYSTEMD_SERVICE" <<EOF
[Unit]
Description=Terminal Manager Telegram Bot
After=network.target

[Service]
WorkingDirectory=/opt/terminal-manager-bot
ExecStart=/opt/terminal-manager-bot/venv/bin/python /opt/terminal-manager-bot/bot.py
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now terminal-manager-bot
    echo "Bot service started."
}

# Main installation process
main() {
    install_packages
    setup_config_dir
    create_nginx_template
    create_utility_script
    create_web_interface
    setup_nginx_ssl
    install_telegram_bot

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
