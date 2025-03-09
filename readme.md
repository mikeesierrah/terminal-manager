# Terminal Manager

Terminal Manager is a centralized web-interface designed to streamline terminal access management. It allows users to navigate to specific terminal via paths and efficiently manage multiple terminal sessions.

For Those Who are tired of SSH Managers and wish their browsers could save their server credential

## Features

- **Centralized Management**: Provides a unified web-interface for managing multiple terminal sessions.
- **Easy Navigation**: Users can quickly access specific terminal paths.
- **Automated Setup**: Install and configure terminal management with simple one-liner scripts.
- **Customizable Interface**: Modify the landing page and assets to fit your organization's branding.

Here’s the Markdown version of your README:


## Usage

### 1. Install the Manager
First, install the Terminal Manager using the installation script:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mikeesierrah/terminal-manager/refs/heads/main/manager.sh)
```

### 2. Configure a Node
Next, set up a node using the Node Terminal script:

```bash
bash <(curl -Ls https://raw.githubusercontent.com/mikeesierrah/terminal-manager/refs/heads/main/node.sh)
```

During setup, you will be prompted for:
- **Username & Password**: This is not your server's login credentials. Use a strong, random username and password.
- **IP Address**: Enter the IP of your main server. This is crucial, as it will restrict access from other IPs.
- **Port**: Specify a port for the node service to listen on. Make sure to note this down for later use.

### 3. Add the Node to the Manager
Once the node is set up, go to the Manager server and add the node using the following command:

```bash
terminal-manager add NODENAME NODE_IP LISTEN_PORT
```

Replace `NODE_IP` and `LISTEN_PORT` with the values you set earlier.

- `NODENAME` is optional, but each terminal must have a unique name.

Then, open your browser and navigate to:

```
https://your-domain.com/NODENAME/
```

You will be prompted for your terminal username and password. Enter the correct credentials to connect.

## Security Recommendations

### Disable SSH on Your Server
For added security, disable SSH access on your server. For Ubuntu 24.04, run:

```bash
sudo systemctl disable --now ssh
```

### Enhance Security with a CDN and CAPTCHA
To further protect access to your terminal, consider placing your domain behind a CDN and enabling CAPTCHA. This helps prevent bots or malicious actors from brute-forcing your credentials.


