// SPDX-License-Identifier: MPL-2.0

use std::{collections::HashMap, net::{IpAddr, Ipv4Addr, Ipv6Addr}};

use chrono::{DateTime, Utc};
use lazy_static::lazy_static;

#[derive(Debug)]
pub struct Entry {
    pub date: DateTime<Utc>,
    pub reason: &'static str,
}

pub fn find(ip: &IpAddr) -> Option<&'static Entry> {
    match ip {
        IpAddr::V4(ipv4) => IPV4.get(ipv4),
        IpAddr::V6(ipv6) => {
            if let Some(ref ipv4) = ipv6.to_ipv4() {
                IPV4.get(ipv4)
            } else {
                IPV6.get(ipv6)
            }
        }
    }
}

macro_rules! blocklist {
    (
        $name:ident : $ty:ty ;
        $(
            $addr:expr => {
                date: $date:literal
                reason: $reason:literal
            }
        )* $(,)?
    ) => {
        lazy_static! {
            static ref $name: HashMap<$ty, Entry> = HashMap::from_iter([
                $(
                    (
                        $addr,
                        Entry {
                            date: $date.parse().expect("failed to parse date/time"),
                            reason: $reason,
                        },
                    ),
                )*
            ]);
        }
    };
}

macro_rules! ipv4_blocklist {
    (
        $(
            $a:literal $b:literal $c:literal $d:literal => {
                $( $field_name:ident : $field_value:literal )*
            }
        ),* $(,)?
    ) => {
        blocklist! {
            IPV4: Ipv4Addr;
            $(
                Ipv4Addr::new($a, $b, $c, $d) => {
                    $(
                        $field_name: $field_value
                    )*
                },
            )*
        }
    };
}

macro_rules! ipv6_blocklist {
    (
        $(
            $addr:literal => { $( $field_name:ident : $field_value:literal )* }
        ),* $(,)?
    ) => {
        blocklist! {
            IPV6: Ipv6Addr;
            $(
                $addr.parse().expect("failed to parse IPv6 address") => {
                    $(
                        $field_name: $field_value
                    )*
                },
            )*
        }
    };
}

include!("blocklist/ipv4.rs");

include!("blocklist/ipv6.rs");
