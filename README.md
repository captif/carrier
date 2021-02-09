carrier for captif
---------------------



### streams

| path                             | description          | usage                                             |
|----------------------------------|----------------------|---------------------------------------------------|
| /v3/carrier.sysinfo.v1/..        | system information   | carrier get sysinfo <identity>                    |
| /v3/genesis.v2/..                | system configuration | carrier genesis <identity>                        |
| /v0/reboot                       | reboot system        | carrier stream <identity> /v0/reboot              |
| /v0/shell                        | shell                | carrier shell <identity>                          |
| /v0/ota                          | firmware update      | carrier fs ota <identity> ota firmware.img        |
| /v0/sft                          | file transfer        | carrier fs push <identity> /localfile /remotefile |
| /v2/captif.proximity.v1/scan     | proximity            | all stations seen in the air including details    |
| /v2/captif.proximity.v1/count    | proximity            | count stations seen in the air                    |
| /v2/captif/sta_block             | station bans         | see sta_block documentation                       |




### proximity scan

scan for other wifi stations in the air, includes probe_requests but also other traffic.
note that the collector doesn't start until you send a config object

keys in config object

| name  | format | description |
|-------|--------|-------------|
| bulk_scan_time        |  u32       | total collected before reporting |
| sampling_interval     |  u32       | pcap interval. do not set |
| max_samples_per_mac   |  u32       | maximum number of seen entries in scan per station |
| anon_hash             |  bytes     | hash mac addresses with this seed before reporting |
| hash_stas_only        |  bool      | only hash mac addresses if they're sta |
| filter_aps            |  bool      | do not report access points |
| min_rss               |  i8        | do not report stations that are received weaker than this |
| min_rss_negative      |  u8        | same, but transmitted without sign |



cli 13 sends a config object automatically using --args

```bash
carrier stream cDEYB2CXZJHDH7VI5DSJFAX32XXQNNTNVN63UfWRPQFQ4TYPAGUAK5JA /v3/captif.proximity.v1/count \
    --args bulk_scan_time=10 \
    --args min_rss_negative=80

```


### sta_block

customer requested endpoint.
used to individually ban clients.
header arguments:


| header    | description                                                  |
|-----------|--------------------------------------------------------------|
| time      | for how long to ban  in milliseconds. set to 0 to remove ban |
| addr      | mac address of client to remove                              |
| interface | interface to ban client from                                 |


example:
```bash
carrier get oWpiPNBufRxmvN03aK7opXXzjRHkyq2kXWnCNUu9JZFatNX /v2/captif/sta_block -H time 10000 -H addr 80:b1:15:92:22:06 -H interface publicap
```



### genesis

see https://github.com/devguardio/genesis
