#!/bin/sh

install_crate() {
    sudo "RUSTUP_HOME=${RUSTUP_HOME}" \
        `which cargo` install --root /usr/local/bin --path "crates/${1}"
}

install_service() {
    sudo cp "systemd/${1}.service" "/etc/systemd/system/${1}.service"
    systemctl enable "${1}.service"
}

install_crate host-db
install_crate services

install_service norepi-hosts-server
install_service norepi-httpd
