#!/bin/sh

# Note: this script should be run under the root user.

install_crate() {
    cargo install --root /usr/local/bin --path "crates/${1}"
}

install_service() {
    cp "systemd/${1}.service" "/etc/systemd/system/${1}.service"
    systemctl enable "${1}.service"
}

install_crate host-db
install_crate services

install_service norepi-hosts-server
install_service norepi-httpd
