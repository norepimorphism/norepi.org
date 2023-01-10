// SPDX-License-Identifier: MPL-2.0

#![feature(addr_parse_ascii)]

use std::{env, fmt, net::IpAddr, process::ExitCode};

use norepi_site_db_hosts::client;

fn main() -> ExitCode {
    match main_impl() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            println!("error: {e}");

            ExitCode::FAILURE
        }
    }
}

enum Error {
    StaticMessage(&'static str),
    HeapMessage(String),
    GetHost(client::GetHostError),
    KillServer(client::RequestError<client::KillServer>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StaticMessage(s) => f.write_str(s),
            Self::HeapMessage(s) => f.write_str(s),
            Self::GetHost(e) => e.fmt(f),
            Self::KillServer(e) => e.fmt(f),
        }
    }
}

fn main_impl() -> Result<(), Error> {
    let mut args = env::args();

    let Some(exe_name) = args.next() else {
        print_usage(env!("CARGO_PKG_NAME"));
        return Err(Error::StaticMessage("argc is 0. What do you want from me?!"));
    };
    let Some(action) = args.next().and_then(|arg| {
        let user_wants_help = matches!(arg.as_str(), "help | -h | --help");

        if user_wants_help {
            None
        } else {
            Some(arg)
        }
    }) else {
        print_usage(exe_name.as_str());
        return Ok(());
    };

    match action.as_str() {
        "get" => do_get(args),
        "kill" => do_kill(),
        action => Err(Error::HeapMessage(format!("unknown action '{action}'."))),
    }
}

fn print_usage(exe_name: &str) {
    println!("USAGE.");
    println!("  {exe_name} (help | -h | --help)");
    println!("    Prints this usage information.");
    println!("  {exe_name} ACTION");
    println!("    Performs the specified action on the server.");
    println!();
    println!("Actions.");
    println!("  get IP-ADDR");
    println!("    Prints the server response to a GetHost request for the host with the specified");
    println!("    IP address. IP-ADDR must be either an IPv4 or IPv6 address.");
    println!("  kill");
    println!("    Kills the server process. This is equivalent to sending a SIGINT signal to the");
    println!("    server process.");
}

fn parse_ip(args: &mut env::Args) -> Result<IpAddr, Error> {
    let Some(ip) = args.next() else {
        return Err(Error::StaticMessage("expected argument IP-ADDR"));
    };

    IpAddr::parse_ascii(ip.as_bytes()).map_err(|e| {
        Error::HeapMessage(format!("failed to parse IP-ADDR: {e}"))
    })
}

fn do_get(mut args: env::Args) -> Result<(), Error> {
    let ip = parse_ip(&mut args)?;
    let response = client::get_host(ip).map_err(Error::GetHost)?;

    match response {
        client::GetHostResponse::NotFound => {
            println!("NOT FOUND.");
        }
        client::GetHostResponse::Found(host) => {
            println!("FOUND.");
            println!();
            // FIXME: print properly-formatted key-value property pairs. Don't just debug-print.
            println!("{:#?}", host);
        }
    }

    Ok(())
}

fn do_kill() -> Result<(), Error> {
    client::kill_server().map_err(Error::KillServer)
}
