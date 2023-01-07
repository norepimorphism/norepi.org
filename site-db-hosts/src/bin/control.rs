// SPDX-License-Identifier: MPL-2.0

#![feature(addr_parse_ascii)]

use std::{env, net::IpAddr};

fn main() {
    let mut args = env::args().skip(1);

    if let Some(action) = args.next() {
        let Some(ip) = args.next() else {
            eprintln!("expected 'ip' argument");
            return;
        };

        let Ok(ip) = IpAddr::parse_ascii(ip.as_bytes()) else {
            eprintln!("failed to parse host");
            return;
        };

        match action.as_str() {
            "get" => {
                match norepi_site_db_hosts::client::get_host(ip) {
                    Ok(response) => match response {
                        norepi_site_db_hosts::client::GetHostResponse::NotFound => {
                            println!("Not found");
                        }
                        norepi_site_db_hosts::client::GetHostResponse::Found(host) => {
                            println!("Found");
                            println!("{:#?}", host);
                        }
                    },
                    Err(e) => {
                        eprintln!("{:#?}", e);
                    }
                }
            }
            "set" => {
                match norepi_site_db_hosts::client::set_host(ip, norepi_site_db_hosts::Host::new()) {
                    Ok(_) => {}
                    Err(e) => {
                        eprintln!("{:#?}", e);
                    }
                }
            }
            _ => todo!(),
        }
    }
}
