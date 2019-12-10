#![feature(generators, generator_trait)]

use carrier::error::Error;
use std::env;
use devguard_genesis as genesis;
use osaka::osaka;
use std::sync::atomic::{AtomicBool, Ordering};
use std::os::unix::io::AsRawFd;
use libc::{c_int};
use rand::Rng;
use nix;

include!(concat!(env!("OUT_DIR"), "/build_id.rs"));
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/captif.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/captif.proximity.v1.rs"));
}


//extern {
//    fn wd_open() -> c_int;
//    fn wd_feed(fd: c_int);
//}

mod proximity;


pub fn spawn_the_rebooter() {
    use chrono::{Datelike, Timelike, Utc};
    use std::fs::File;
    use std::io::Read;

    std::thread::spawn(move || {
        loop {
            let mut f = File::open("/proc/uptime").unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            let mut s = s.split_whitespace();
            let uptime = s.next().unwrap().parse::<f64>().unwrap() as u64;

            if uptime > 3600 {
                let now = Utc::now();
                if now.hour()  == 7 || now.hour() == 19 {
                    // wait a random amount of minutes to avoid rebooting the entire fleet at once
                    let n : u8 = rand::thread_rng().gen();
                    std::thread::sleep(std::time::Duration::from_secs(n as u64));

                    nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT);
                    return;
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(3600));
        }
    });
}





static WATCHDOG:    AtomicBool = AtomicBool::new(false);

#[osaka]
pub fn publisher(poll: osaka::Poll, config: carrier::config::Config) -> Result<(), Error> {
    use osaka::Future;

    std::thread::spawn(move || {
        use std::time::Instant;

        let mut now = Instant::now();



        /*
         * TODO real watchdog is too risky right now.
         * sysupdate will kill carrier, and that's actually correct.
         *
        let wd = unsafe {
            let wd = wd_open();
            wd_feed(wd);
            wd
        };
        */

        loop {
            if WATCHDOG.swap(false, Ordering::Relaxed) {
                now = Instant::now();
            }

            if now.elapsed().as_secs() > 90 {
                log::error!("publisher loop stuck. rebooting");
                nix::sys::reboot::reboot(nix::sys::reboot::RebootMode::RB_AUTOBOOT);
                std::process::exit(1);
                return;

            } else {
                //unsafe {
                //    wd_feed(wd);
                //}
            }

            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    });



    let mut publisher   = carrier::publisher::new(config)
        .route("/v0/shell",                             None,       carrier::publisher::shell::main)
        .route("/v0/sft",                               None,       carrier::publisher::sft::main)
        .route("/v0/reboot",                            None,       reboot)
        .route("/v0/ota",                               None,       carrier::publisher::openwrt::ota)
        .route("/v2/carrier.certificate.v1/authorize",  Some(1024), carrier::publisher::authorization::main)
        .route("/v2/carrier.sysinfo.v1/sysinfo",        None,       carrier::publisher::sysinfo::sysinfo)
        .route("/v2/carrier.sysinfo.v1/netsurvey",      None,       carrier::publisher::openwrt::netsurvey)
        .route("/v2/genesis.v1",                        Some(4048), genesis::genesis_stream)
        .route("/v2/captif/sta_block",                  None,       sta_block)
        .route("/v2/captif.proximity.v1/scan",          None,       proximity::scan)
        .route("/v2/captif.proximity.v1/count",         None,       proximity::count)
        .with_disco("captif".to_string(), BUILD_ID.to_string())
        .on_pub(||{
            genesis::stabilize(true)
        })
        .publish(poll.clone());


    loop {
        match publisher.poll() {
            osaka::FutureResult::Done(y) => return y,
            osaka::FutureResult::Again(y) => {
                WATCHDOG.store(true, Ordering::Relaxed);
                yield y;
            }
        }
    }
}

pub fn main() -> Result<(), Error> {
    if let Err(_) = env::var("RUST_LOG") {
        env::set_var("RUST_LOG", "info");
    }
    tinylogger::init().ok();



    let mut args = std::env::args();
    args.next();
    match args.next().as_ref().map(|v|v.as_str()) {
        Some("publish") => {
            std::thread::sleep(std::time::Duration::from_secs(1));
            genesis::stabilize(false);

            let poll    = osaka::Poll::new();
            let config  = carrier::config::load()?;
            publisher(poll, config).run()?;


        }
        Some("identity") => {
            let config = carrier::config::load()?;
            println!("{}", config.secret.identity());
        }
        Some("genesis") => {
            genesis::genesis().unwrap();
        }
        Some("lolcast") => {
            let config = carrier::config::load()?;
            let msg = format!("CR1:BTN:{}", config.secret.identity()).as_bytes().to_vec();
            let socket = std::net::UdpSocket::bind("224.0.0.251:0")?;
            socket.set_broadcast(true).expect("set_broadcast call failed");
            socket.send_to(&msg, "224.0.0.251:8444").expect("couldn't send message");
            socket.send_to(&msg, "0.0.0.0:8444").expect("couldn't send message");
        }
        _ => {
            eprintln!("cmds: publish, identity, genesis, lolcast");
        }
    }

    Ok(())
}

pub fn reboot(
    _poll: osaka::Poll,
    _headers: carrier::headers::Headers,
    _identity: &carrier::identity::Identity,
    mut stream: carrier::endpoint::Stream,
) -> Option<osaka::Task<()>> {
    use std::process::Command;
    stream.send(carrier::headers::Headers::ok().encode());
    Command::new("/bin/sh")
        .args(vec!["-c" , "reboot"])
        .spawn().unwrap();
    None
}


pub fn sta_block(
    _poll: osaka::Poll,
    headers: carrier::headers::Headers,
    _identity: &carrier::identity::Identity,
    mut stream: carrier::endpoint::Stream,
) -> Option<osaka::Task<()>> {
    use std::process::Command;

    let ban_time = match headers.get(b"time").and_then(|v|String::from_utf8_lossy(v).parse::<u64>().ok()) {
        Some(v) => v,
        None  => {
            stream.send(carrier::headers::Headers::with_error(400, "time header invalid or missing").encode());
            return None;
        }
    };

    let addr = match headers.get(b"addr") {
        Some(v) => String::from_utf8_lossy(&v),
        None  => {
            stream.send(carrier::headers::Headers::with_error(400, "addr header missing").encode());
            return None;
        }
    };

    let interface = match headers.get(b"interface") {
        Some(v) => String::from_utf8_lossy(&v),
        None  => {
            stream.send(carrier::headers::Headers::with_error(400, "interface header missing").encode());
            return None;
        }
    };

    let deauth : bool = headers.get(b"deauth").and_then(|v|String::from_utf8_lossy(v).parse::<bool>().ok()).unwrap_or(true);


    let status = Command::new("/bin/ubus")
        .arg("call")
        .arg(format!("hostapd.{}", interface))
        .arg("del_client")
        .arg(format!("{{'addr':'{}', 'reason':5, 'deauth':{} , 'ban_time':{}}}", addr, deauth, ban_time))
        .status();

    let status = match status {
        Ok(v) => v,
        Err(e) => {
            stream.send(carrier::headers::Headers::with_error(500, format!("cannot call ubus: {}", e)).encode());
            return None;
        }
    };

    if !status.success() {
        stream.send(carrier::headers::Headers::with_error(500, "ubus call failed").encode());
        return None;
    };

    stream.send(carrier::headers::Headers::ok().encode());

    None
}


