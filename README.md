# 🛡️ NGINX HIBP -  Credential Alert Module

```
 _   _ _____ _____ _   ___   __    _    _ _____ ____  _____  
| \ | |  __ \_   _| \ | \ \ / /   | |  | |_   _|  _ \|  __ \ 
|  \| | |  \/ | | |  \| |\ V /    | |__| | | | | |_) | |__) |
| . ` | | __  | | | . ` | > <     |  __  | | | |  _ <|  ___/ 
| |\  | |_\ \_| |_| |\  |/ . \    | |  | |_| |_| |_) | |     
|_| \_|\____/_____|_| \_/_/ \_\   \_|  |_|_____|____/|_|     
                                                             
     🔒 Monitor Your Credentials & Alert
```

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![[CI/CD]](https://github.com/alimaharramli/nginx_hibp/actions/workflows/docker-build.yml/badge.svg)
[![Docker Package](https://img.shields.io/badge/docker-ghcr.io-blue)](https://github.com/alimaharramli/nginx_hibp/pkgs/container/nginx_hibp)

<div align="center">
  <strong>An NGINX module that checks login passwords and alerts on compromised credentials.</strong><br>
  This module integrates with Have I Been Pwned (HIBP) API to check for compromised passwords and provides webhook notifications for security incidents.
</div>

---

## ✨ Features

<div align="center">

| Feature | Description |
|---------|-------------|
| 🔒 **Real-time Detection** | Check user credentials for any website |
| 🔍 **HIBP Integration** | Check against Have I Been Pwned database |
| 📨 **Instant Alerts** | Webhook notifications for credential matches |
| 📝 **Detailed Logging** | Logging for credential matches |
| 🐳 **Docker Support** | Easy deployment with containers |
| 📄 **Request Format Support** | Handles both form data and JSON request bodies |

</div>

## 🔐 How It Works: k-Anonymity

This module implements k-anonymity when checking passwords against the HIBP database, providing an additional layer of security. Here's how it works:

1. When a password is submitted, instead of sending the complete hash to HIBP:
   - The password is first hashed (SHA-1)
   - Only the first 5 characters of the hash are sent to the API
   - This creates an anonymized "bucket" of possible matches

2. The HIBP API returns all hash suffixes (remaining 35 characters) that match the first 5 characters
   - This typically returns 300-600 hash suffixes
   - The complete hash is never sent to the API

3. The module then locally compares the full hash against the returned suffixes
   - If a match is found, the password has been compromised
   - If no match is found, the password is considered secure

This approach ensures:
- The complete password hash is never transmitted
- The API service never gains enough information about non-breached passwords
- Maintains security while allowing efficient password checking

For more details about the k-anonymity implementation, see [Cloudflare's detailed explanation](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/).

## Installation

### Using Docker

1. Create a `nginx.conf` file:
   ```nginx
    http {
        server {
            listen 80;
            server_name localhost;

            location / {
                # Required configuration
                cred_alert_target_url "https://webhook.site/xxxx";  # Your webhook URL
                cred_alert_log_file "/usr/local/nginx/logs/cred_alert.log";

                proxy_pass https://example.com;
            }
        }
    }

    events {
        worker_connections  1024;
    }
   ```

2. Pull the image from GitHub Container Registry:
   ```bash
   docker pull ghcr.io/alimaharramli/nginx_hibp:main
   ```

3. Run the container with your config:
   ```bash
   docker run -d -p 80:80 -p 443:443 -v $(pwd)/nginx.conf:/usr/local/nginx/conf/nginx.conf ghcr.io/alimaharramli/nginx_hibp:main
   ```

#### Quick Testing Environment

For a quick test of the module:

   ```bash
   cd test && mkdir -p nginx/logs && chmod 777 nginx/logs && docker compose up --build
   ```
This will set up a testing environment with login-only demo app

### Manual Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/alimaharramli/nginx_hibp.git
   ```

2. Install dependencies (Ubuntu/Debian example):
   ```bash
   apt-get install build-essential libssl-dev libpcre3-dev zlib1g-dev libcurl4-openssl-dev libjansson-dev
   ```

3. Download and compile NGINX with the module:
   ```bash
   wget http://nginx.org/download/nginx-1.21.6.tar.gz
   tar -zxvf nginx-1.21.6.tar.gz
   cd nginx-1.21.6
   ./configure \
    --prefix=/usr/local/nginx \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-cc-opt="-Os -fomit-frame-pointer -I/usr/include/jansson -I/usr/include/openssl -I/usr/include/curl" \
    --with-ld-opt="-Wl,--as-needed -ljansson -lssl -lcrypto -lcurl" \
    --add-module=./ngx_http_cred_alert_module \
    --user=nginx \
    --group=nginx 
   make
   sudo make install
   ```

## Configuration

Add the following directives to your NGINX configuration:

```nginx
location / {
            # Required configuration
            cred_alert_target_url "https://webhook.site/";  # Webhook URL to send alerts to
            cred_alert_log_file "/usr/local/nginx/logs/cred_alert.log";  # Path to log file for alerts
            
            # Optional: HIBP API configuration 
            # Set custom URL for local HIBP deployment - https://github.com/oschonrock/hibp
            cred_alert_hibp_url "https://api.localhibp.com/range/";
            
            # Optional: Custom form field mappings
            # Modify if your application uses different field names
            cred_alert_username_field "my_custom_username";  # Default: "username"
            cred_alert_password_field "my_custom_password";  # Default: "password" 
            cred_alert_email_field "my_custom_email";       # Default: "email"
            
            # Optional: Request filtering
            # Only check specific requests
            cred_alert_uri_filter "/my_custom_uri";    # Only check requests to this URI
            cred_alert_status_filter 404;              # Only check requests with this response code
}
```

## Module Components

- **Core Module** (`ngx_http_cred_alert_module.c`): Main module implementation
- **HIBP Integration** (`cred_alert_hibp.c`): Have I Been Pwned API integration
- **Webhook Notifications** (`cred_alert_webhook.c`): Security alert notifications
- **Logging** (`cred_alert_log.c`): Event logging functionality

## Sample Output

### Log Format
The module logs credential checks in the following format:
```
[2025-03-01 22:12:07] 172.21.0.1 - localhost - POST - /login - admin - 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8 - 302
```

### Webhook Notification Format
When a credential match is found, a JSON payload is sent to the configured webhook URL:
```json
{
  "password_hash": "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8",
  "username": "admin",
  "request_uri": "/login",
  "remote_ip": "172.21.0.1",
  "method": "POST",
  "status_code": 302,
  "host": "localhost"
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- NGINX team for their excellent web server
- Have I Been Pwned for their password breach API
