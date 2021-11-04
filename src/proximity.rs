use std::process::Command;
use std::thread;
use enum_primitive::FromPrimitive;
use std::collections::HashMap;
use std::time::{Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use sha2::{Sha256, Digest};
use enum_primitive::*;
use log::{warn, error};
use carrier_rs::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use mio_extras::channel;
use std::sync::mpsc;
use osaka::osaka;
use osaka::mio;
use super::proto;
use std::sync::{Arc, Mutex};
use lazy_static::lazy_static;

enum_from_primitive! {
#[derive(Debug, PartialEq)]
    pub enum FrameType {

        // Managment
        AssociationRequest      = 0b00000000,
        AssociationResponse     = 0b00010000,
        ReassociationRequest    = 0b00100000,
        ReassociationResponse   = 0b00110000,
        ProbeRequest            = 0b01000000,
        ProbeResponse           = 0b01010000,
        Beacon                  = 0b10000000,
        Atim                    = 0b10010000,
        Disassociation          = 0b10100000,
        Authentication          = 0b10110000,
        Deauthentication        = 0b11000000,
        Action                  = 0b11010000,

        //Control
        BlockAckRequest         = 0b10000100,
        BlockAck                = 0b10010100,
        PsPoll                  = 0b10100100,
        Rts                     = 0b10110100,
        Cts                     = 0b11000100,
        Ack                     = 0b11010100,
        CfEnd                   = 0b11100100,
        CfEndCfAck              = 0b11110100,

        // Data
        Data                    = 0b00001000,
        DataCfAck               = 0b00011000,
        DataCfPoll              = 0b00101000,
        DataCfAckCfPoll         = 0b00111000,
        Null                    = 0b01001000,
        CfAck                   = 0b01011000,
        CfPoll                  = 0b01101000,
        CfAckCfPoll             = 0b01111000,
        QosData                 = 0b10001000,
        QosDataCfAck            = 0b10011000,
        QosDataCfPoll           = 0b10101000,
        QosDataCfAckCfPoll      = 0b10111000,
        QosNUll                 = 0b11001000,
        QosCfPoll               = 0b11101000,
        QosCfAck                = 0b11111000,

    }
}


const DEFAULT_BULK_SCAN_TIME : u32  = 30;
const DEFAULT_SAMPLING_INTERVAL: u32  = 2000;

#[derive(Debug)]
pub enum Error {
    NoSuchDevice,
    Pcap(pcap::Error),
}

impl From<pcap::Error> for Error {
    fn from(pcap: pcap::Error) -> Error {
        Error::Pcap(pcap)
    }
}

pub fn open(name: &str, sampling: u32) -> Result<pcap::Capture<pcap::Active>, Error> {
    for device in pcap::Device::list().expect("pcap device list") {
        if device.name == name {
            return Ok(pcap::Capture::from_device(device)?
                .promisc(true)
                .snaplen(512)
                .timeout(sampling as i32)
                .open()?);
        }
    }
    return Err(Error::NoSuchDevice);
}



pub fn mac_to_str(b: &[u8]) -> String {
    format!("{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5])
}


pub fn ts() -> u64{
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() * 1000 + since_the_epoch.subsec_nanos() as u64 / 1_000_000
}

lazy_static! {
    pub static ref COLLECTALL : Arc<Mutex<proto::WifiFullCollect>>  = Arc::new(Mutex::new(proto::WifiFullCollect {
        timestamp:  0,
        stations:   HashMap::new(),
    }));

    pub static ref COLLECTSTART : Arc<Mutex<std::time::Instant>> = Arc::new(Mutex::new(std::time::Instant::now()));
}

pub fn collect(
    cap: &mut pcap::Capture<pcap::Active>,
    bulk_scan_time: u32,
    min_rss: Option<i8>,
    filter_aps: bool
    ) -> proto::WifiFullCollect
{
    std::mem::replace(&mut *COLLECTALL.lock().unwrap(), proto::WifiFullCollect {
        timestamp:  ts(),
        stations:   HashMap::new(),
    });
    std::mem::replace(&mut *COLLECTSTART.lock().unwrap(), Instant::now());

    loop {
        let pkt = match cap.next() {
            Err(e) => {
                warn!("{}", e);
                thread::sleep(std::time::Duration::from_secs(1));
                continue;
            },
            Ok(v) => v,
        };
        let radiotap = match radiotap::Radiotap::from_bytes(&pkt) {
            Err(e) => {
                warn!("{}", e);
                continue;
            },
            Ok(v) => v,
        };

        let pkt = &pkt[radiotap.header.length..];
        let ft = FrameType::from_u8(pkt[0]);
        let ft = match ft {
            None    => continue,
            Some(v) => v,
        };

        match ft {
            FrameType::Beacon => {
                if filter_aps {
                    continue;
                }
                let bssid = mac_to_str(&pkt[16..22]);

                let mut at   = 36;
                let mut ssid = None;

                loop {
                    let tag = pkt[at];
                    at += 1;
                    let len = pkt[at] as usize;
                    at += 1;
                    if tag == 0 {
                        ssid = Some(String::from_utf8_lossy(&pkt[at..at+len]).to_string());
                        break;
                    }
                    at += len;
                    if at >= pkt.len() - 4 {
                        break;
                    }
                }

                if let Ok(mut xa) =  COLLECTALL.try_lock() {
                    let sta = xa.stations.entry(bssid).or_insert(proto::WifiFullStationCollect {
                        frequency: match radiotap.channel {
                            Some(v) => v.freq as u32,
                            None => continue,
                        },
                        seen: Vec::new(),
                        ssid: String::new(),
                        side: Vec::new(),
                    });
                    sta.ssid = ssid.unwrap_or(String::new());

                    if let Some(ant) = radiotap.antenna_signal {
                        let frq =  radiotap.channel.map(|v|v.freq).unwrap_or(0);

                        let elapsed = COLLECTSTART.lock().unwrap().elapsed();
                        let elapsed = elapsed.as_secs() * 1000 + elapsed.subsec_millis() as u64;

                        if let Some(min_rss) = min_rss {
                            if ant.value < min_rss {
                                continue;
                            }
                        }

                        sta.seen.push(proto::WifiFullStationSeen{
                            tsoffset:   elapsed,
                            rss: ant.value as i32,
                            frequency: frq as u32
                        });
                    }
                }
            },
            FrameType::ProbeRequest|
                FrameType::Data|
                FrameType::DataCfAck|
                FrameType::DataCfPoll|
                FrameType::DataCfAckCfPoll|
                FrameType::Null|
                FrameType::CfAck|
                FrameType::CfPoll|
                FrameType::CfAckCfPoll|
                FrameType::QosData|
                FrameType::QosDataCfAck|
                FrameType::QosDataCfPoll|
                FrameType::QosDataCfAckCfPoll|
                FrameType::QosNUll|
                FrameType::QosCfPoll|
                FrameType::QosCfAck => {
                    let addr2 = mac_to_str(&pkt[10..16]);
                    let mut xa =  COLLECTALL.lock().unwrap();
                    let sta = xa.stations.entry(addr2).or_insert(proto::WifiFullStationCollect{
                        frequency: match radiotap.channel {
                            Some(v) => v.freq as u32,
                            None => continue,
                        },
                        seen: Vec::new(),
                        ssid: String::new(),
                        side: Vec::new(),
                    });
                    if let Some(ant) = radiotap.antenna_signal {
                        let frq =  radiotap.channel.map(|v|v.freq).unwrap_or(0);

                        let elapsed = COLLECTSTART.lock().unwrap().elapsed();
                        let elapsed = elapsed.as_secs() * 1000 + elapsed.subsec_millis() as u64;

                        if let Some(min_rss) = min_rss {
                            if ant.value < min_rss {
                                continue;
                            }
                        }

                        sta.seen.push(proto::WifiFullStationSeen{
                            tsoffset:   elapsed,
                            rss: ant.value as i32,
                            frequency: frq as u32
                        });
                    }
                },
            _ => (),
        }

        let elapsed = COLLECTSTART.lock().unwrap().elapsed();
        let elapsed = elapsed.as_secs() as u64 * 1000 + elapsed.subsec_millis() as u64;
        if elapsed >= bulk_scan_time as u64 * 1000 {
            break;
        }
    }

    let ca = COLLECTALL.lock().unwrap();
    return ca.clone()
}




struct PoopsyncClient {
    last_seen:  std::time::Instant
}

impl Default for PoopsyncClient {
    fn default() -> Self {
        PoopsyncClient {
            last_seen: std::time::Instant::now()
        }
    }
}

fn as_u32_le(array: &[u8]) -> u32 {
    ((array[0] as u32) << 24) +
    ((array[1] as u32) << 16) +
    ((array[2] as u32) <<  8) +
    ((array[3] as u32) <<  0)
}


pub fn init() {
    let mut socket_ = std::net::UdpSocket::bind("0.0.0.0:3312").unwrap();

    let mut clients_ : std::sync::Arc<std::sync::Mutex<HashMap<std::net::SocketAddr, PoopsyncClient>>>
        = std::sync::Arc::new(std::sync::Mutex::new(HashMap::new()));

    let mut clients = clients_.clone();
    let socket = socket_.try_clone().expect("couldn't clone the socket");

    thread::spawn(move ||{
        let mut buf = [0; 1000];
        loop {
            if let Ok((amt, src)) = socket.recv_from(&mut buf) {

                {
                    let mut clients = clients.lock().unwrap();
                    let mut entry = clients.entry(src).or_insert(PoopsyncClient::default());
                    entry.last_seen = std::time::Instant::now();
                }

                if amt > 4 {
                    let id  = as_u32_le(&buf[0..4]);
                    let cmd = String::from_utf8_lossy(&buf[4..amt]);
                    let cmd = cmd.trim();
                    if cmd.starts_with("(((") {
                        println!("ps {} {} {}", src, id, cmd);
                        if cmd == "(((ping)))" {
                            socket.send_to(&[b'p'], src);
                        } else if cmd.starts_with("(((pkt") {
                            let cmd = cmd.split(";").collect::<Vec<&str>>();
                            if cmd.len() >= 7 {
                                let chan = cmd[2];
                                let tp   = cmd[3];
                                let rss  = cmd[4];
                                let mac  = cmd[5].to_string();


                                let freq = match chan {
                                        "1"  => 2412,
                                        "2"  => 2417,
                                        "3"  => 2422,
                                        "4"  => 2427,
                                        "5"  => 2432,
                                        "6"  => 2437,
                                        "7"  => 2442,
                                        "8"  => 2447,
                                        "9"  => 2452,
                                        "10" => 2457,
                                        "11" => 2462,
                                        "12" => 2467,
                                        "13" => 2472,
                                        "14" => 2484,
                                        _    => 0,
                                };

                                if tp == "0x0040" {
                                    let elapsed = COLLECTSTART.lock().unwrap().elapsed();
                                    let elapsed = elapsed.as_secs() * 1000 + elapsed.subsec_millis() as u64;

                                    let mut xa =  COLLECTALL.lock().unwrap();
                                    let sta = xa.stations.entry(mac).or_insert(proto::WifiFullStationCollect{
                                        frequency:  freq,
                                        seen:       Vec::new(),
                                        ssid:       String::new(),
                                        side:       Vec::new(),
                                    });
                                    sta.side.push(proto::WifiStationSeenBySidekick{
                                        tsoffset:   elapsed,
                                        esp_id:     id as u64,
                                        rss:        rss.parse::<i32>().unwrap_or(0),
                                        frequency:  freq,
                                    });
                                }
                            }
                        }
                    }
                }


            }
        }
    });


    let mut clients = clients_.clone();
    thread::spawn(move ||{
        loop {
            for channel in (1..12) {

                println!("\n\n\n--> CHANNEL {}", channel);

                {
                    let mut clients = clients.lock().unwrap();
                    let mut remove = Vec::new();
                    for (src, client) in clients.iter() {
                        if client.last_seen.elapsed().as_secs() >= 5 {
                            remove.push(src.clone());
                        }

                        let buf = match channel {
                            1 => [b'1'],
                            2 => [b'2'],
                            3 => [b'3'],
                            4 => [b'4'],
                            5 => [b'5'],
                            6 => [b'6'],
                            7 => [b'7'],
                            8 => [b'8'],
                            9 => [b'9'],
                            10 => [b'a'],
                            11 => [b'b'],
                            12 => [b'c'],
                            13 => [b'd'],
                            _ => [b'1'],
                        };
                        socket_.send_to(&buf, src);
                    }
                    for remove in &remove {
                        clients.remove(remove);
                    }
                }

                Command::new("iw")
                    .args(&["dev",  "monitor", "set", "channel", &format!("{}", channel)])
                    .status();


                std::thread::sleep(std::time::Duration::from_millis(1000));
            }
        }
    });
}


struct DaScanna {
    stop:   mpsc::Sender<()>,
    device: pcap::Capture<pcap::Active>,
}

impl DaScanna {
    pub fn open(sampling_interval: u32) -> Result<Self, String> {
        let device = open("monitor", sampling_interval).map_err(|e|format!("{:?}",e))?;

        let (stop, stop_rx) = mpsc::channel();

        Ok(Self {
            stop,
            device,
        })
    }
}

pub fn scan(poll: osaka::Poll, headers: headers::Headers, _: &identity::Identity, stream: endpoint::Stream)
    -> Option<osaka::Task<()>>
{
    Some(scan_(poll, headers, stream))
}

#[osaka]
fn scan_(poll: osaka::Poll, headers: headers::Headers, mut stream: endpoint::Stream)
{
    let bulk_scan_time = headers.get(b"BULK_SCAN_TIME")
        .and_then(|v|String::from_utf8_lossy(v).parse::<u32>().ok()).unwrap_or(DEFAULT_BULK_SCAN_TIME);
    let sampling_interval = headers.get(b"SAMPLING_INTERVAL")
        .and_then(|v|String::from_utf8_lossy(v).parse::<u32>().ok()).unwrap_or(DEFAULT_SAMPLING_INTERVAL);
    let anon_hash      = headers.get(b"SCAN_MAC_HASH")
        .map(|v|v.to_vec());
    let hash_stas_only : bool = headers.get(b"NO_HASH_APS")
        .and_then(|v|String::from_utf8_lossy(v).parse().ok()).unwrap_or(false);
    let filter_aps     : bool = headers.get(b"FILTER_APS")
        .and_then(|v|String::from_utf8_lossy(v).parse().ok()).unwrap_or(false);
    let min_rss = headers.get(b"RSS_THRESHOLD").and_then(|v|String::from_utf8_lossy(v).parse::<i8>().ok());


    let mut scanna = match DaScanna::open(sampling_interval) {
        Ok(v) => v,
        Err(e) => {
            stream.send(headers::Headers::with_error(503, format!("{}", e).as_bytes()).encode());
            return;
        }
    };
    stream.send(headers::Headers::ok().encode());


    let (tx, rx) = channel::channel();
    thread::spawn(move ||{
        loop {
            let mut collect = collect(&mut scanna.device, bulk_scan_time, min_rss, filter_aps);

            if let Some(ref anon_hash) = anon_hash {
                let mut anonmap = HashMap::new();
                for (k, mut v) in collect.stations.drain() {

                    if hash_stas_only && v.ssid != "" {
                        anonmap.insert(k,v);
                        continue;
                    }

                    let mut hasher = Sha256::new();
                    hasher.input(k.as_bytes());
                    hasher.input(&anon_hash);
                    let k = format!("sha256:{:x}", hasher.result());

                    if !v.ssid.is_empty() {
                        let mut hasher = Sha256::new();
                        hasher.input(v.ssid.as_bytes());
                        hasher.input(&anon_hash);
                        v.ssid = format!("sha256:{:x}", hasher.result());
                    }

                    anonmap.insert(k,v);
                }
                collect.stations = anonmap;
            }

            if let Err(_) = tx.send(collect) {
                println!("collect channel died. exit collect thread");
                return;
            };
        }
    });

    let token = poll
        .register(&rx, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();

    loop {
        match rx.try_recv() {
            Ok(v) => {
                stream.message(v);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                yield poll.again(token.clone(), None);
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return;
            }
        }
    }
}

pub fn count(poll: osaka::Poll, headers: headers::Headers, _: &identity::Identity, stream: endpoint::Stream)
    -> Option<osaka::Task<()>>
{
    Some(count_(poll, headers, stream))
}

#[osaka]
pub fn count_(poll: osaka::Poll, headers: headers::Headers, mut stream: endpoint::Stream)
{
    let bulk_scan_time = headers.get(b"BULK_SCAN_TIME")
        .and_then(|v|String::from_utf8_lossy(v).parse::<u32>().ok()).unwrap_or(DEFAULT_BULK_SCAN_TIME);
    let sampling_interval = headers.get(b"SAMPLING_INTERVAL")
        .and_then(|v|String::from_utf8_lossy(v).parse::<u32>().ok()).unwrap_or(DEFAULT_SAMPLING_INTERVAL);
    let min_rss = headers.get(b"RSS_THRESHOLD").and_then(|v|String::from_utf8_lossy(v).parse::<i8>().ok());

    let mut scanna = match DaScanna::open(sampling_interval) {
        Ok(v) => v,
        Err(e) => {
            stream.send(headers::Headers::with_error(503, format!("{}", e).as_bytes()).encode());
            return;
        }
    };
    stream.send(headers::Headers::ok().encode());

    let (tx, rx) = channel::channel();
    thread::spawn(move ||{
        loop {
            let collect = collect(&mut scanna.device, bulk_scan_time, min_rss, true);
            let mut counter = 0;
            for (_ , station) in &collect.stations {
                if station.seen.len() > 0 {
                    counter += 1;
                }
            }
            let collect = proto::WifiStationCounter {
                timestamp:  collect.timestamp,
                stations:   counter,
            };
            if let Err(_) = tx.send(collect) {
                println!("collect channel died. exit collect thread");
                return;
            };
        }
    });

    let token = poll
        .register(&rx, mio::Ready::readable(), mio::PollOpt::level())
        .unwrap();

    loop {
        match rx.try_recv() {
            Ok(v) => {
                stream.message(v);
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {
                yield poll.again(token.clone(), None);
            }
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return;
            }
        }
    }
}
