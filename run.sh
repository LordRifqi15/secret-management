#!/bin/zsh
export APP_KEK=$(openssl rand -hex 32)
RUST_LOG=info cargo run 
#cargo run
