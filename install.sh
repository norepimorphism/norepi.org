#!/bin/sh

install_crate() {
    cargo install --path "crates/${1}"
}

install_service() {
    sudo ln -s "${HOME}/.cargo/bin/${1}" "/usr/local/bin/${1}"
    sudo cp "systemd/${1}.service" "/etc/systemd/system/${1}.service"
    sudo systemctl enable "${1}.service"
}

install_crate host-db
install_crate services

install_service norepi-hosts-server
install_service norepi-httpd
