# Use Alpine Linux as the base image
FROM alpine:3.16

# Install build dependencies for Nginx and your module
RUN apk add --no-cache \
    build-base \
    linux-headers \
    openssl-dev \
    pcre-dev \
    zlib-dev \
    curl-dev \
    jansson-dev \
    wget \
    git \
    openssl \
    pcre \
    zlib \
    curl \
    jansson

# Create nginx user and group
RUN addgroup -S nginx && \
    adduser -S -G nginx -H -D nginx

# Download and unpack Nginx source
ARG NGINX_VERSION=1.21.6
RUN wget http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxvf nginx-${NGINX_VERSION}.tar.gz && \
    rm nginx-${NGINX_VERSION}.tar.gz

# Copy the Nginx module source into the build context
COPY ngx_http_cred_alert_module /nginx-${NGINX_VERSION}/ngx_http_cred_alert_module

# Set the working directory to the Nginx source directory
WORKDIR /nginx-${NGINX_VERSION}

# Compile Nginx with the additional module
RUN ./configure \
    --prefix=/usr/local/nginx \
    --with-http_ssl_module \
    --with-http_v2_module \
    --with-cc-opt="-Os -fomit-frame-pointer -I/usr/include/jansson -I/usr/include/openssl -I/usr/include/curl" \
    --with-ld-opt="-Wl,--as-needed -ljansson -lssl -lcrypto -lcurl" \
    --add-module=./ngx_http_cred_alert_module \
    --user=nginx \
    --group=nginx && \
    make && make install

# Create necessary directories and set permissions
RUN mkdir -p /usr/local/nginx/logs && \
    touch /usr/local/nginx/logs/cred_alert.log && \
    chown -R nginx:nginx /usr/local/nginx && \
    chmod 644 /usr/local/nginx/logs/cred_alert.log

# Expose ports
EXPOSE 80 443

# Set the working directory to Nginx installation directory
WORKDIR /usr/local/nginx

# Switch to nginx user
USER nginx

# Command to run Nginx
CMD ["sbin/nginx", "-g", "daemon off;"]
