#!/bin/zsh

# WARNING: Generating a new KEK each restart invalidates ALL previously
# encrypted data. In production, set APP_KEK to a persistent, secret value
# stored in a vault or encrypted config. This script is for development only.

set -e

SWAGGER=false
if [[ "$1" == "--with-swagger" || "$1" == "-s" ]]; then
    SWAGGER=true
fi

export APP_KEK=$(openssl rand -hex 32)
export APP_API_KEY=${APP_API_KEY:-$(openssl rand -hex 16)}

echo "⚠  Development mode: KEK is ephemeral. All encrypted data lost on restart."
echo "   API Key: $APP_API_KEY"
if $SWAGGER; then
    echo "   Swagger UI: http://localhost:8080/swagger-ui"
    ENABLE_SWAGGER=true cargo run
else
    echo "   Start with --with-swagger to enable Swagger UI"
    cargo run
fi
