// SPDX-License-Identifier: MPL-2.0

#![feature(addr_parse_ascii)]

use std::{env, net::IpAddr, process};

use error_stack::{IntoReport as _, Result, ResultExt as _};
use norepi_site_db_hosts::client;

fn main() -> process::ExitCode {
    norepi_site_util::run(main_impl)
}

#[derive(thiserror::Error, Debug)]
enum Error {
    #[error("argc is 0. What do you want from me?!")]
    NoArgs,
    #[error("action is invalid")]
    InvalidAction,
    #[error("'get' action failed")]
    DoGet,
    #[error("'kill' action failed")]
    DoKill,
}

fn main_impl() -> Result<(), Error> {
    let mut args = env::args();

    let Some(exe_name) = args.next() else {
        print_usage(env!("CARGO_PKG_NAME"));
        error_stack::bail!(Error::NoArgs);
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
        "get" => do_get(args).change_context(Error::DoGet),
        "kill" => do_kill().change_context(Error::DoKill),
        _ => Err(error_stack::report!(Error::InvalidAction)),
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

#[derive(thiserror::Error, Debug)]
enum ParseIpError {
    #[error("expected argument IP-ADDR")]
    NoArg,
    #[error("IpAddr::parse_ascii() failed")]
    Parse,
}

fn parse_ip(args: &mut env::Args) -> Result<IpAddr, ParseIpError> {
    let Some(ip) = args.next() else {
        error_stack::bail!(ParseIpError::NoArg);
    };

    IpAddr::parse_ascii(ip.as_bytes()).into_report().change_context(ParseIpError::Parse)
}

#[derive(thiserror::Error, Debug)]
enum DoGetError {
    #[error("failed to parse IP address")]
    ParseIp,
    #[error("client::get_host() failed")]
    GetHost,
}

fn do_get(mut args: env::Args) -> Result<(), DoGetError> {
    let ip = parse_ip(&mut args).change_context(DoGetError::ParseIp)?;
    let response = client::get_host(ip).change_context(DoGetError::GetHost)?;

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

#[derive(thiserror::Error, Debug)]
enum DoKillError {
    #[error("client::kill_server() failed")]
    KillServer,
}

fn do_kill() -> Result<(), DoKillError> {
    client::kill_server().change_context(DoKillError::KillServer)
}
