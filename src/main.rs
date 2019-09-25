#![feature(generators, generator_trait)]

use carrier::error::Error;
use std::env;
use devguard_genesis as genesis;

include!(concat!(env!("OUT_DIR"), "/build_id.rs"));
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/captif.v1.rs"));
    include!(concat!(env!("OUT_DIR"), "/captif.proximity.v1.rs"));
}

mod proximity;

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
            let poll            = osaka::Poll::new();
            let config          = carrier::config::load()?;
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
                .on_pub(||genesis::stabilize(true))
                .publish(poll);
            publisher.run()?;
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


