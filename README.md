carrier for captif
---------------------



### streams

| path                             | description          | usage                                             |
|----------------------------------|----------------------|---------------------------------------------------|
| /v0/ota                          | firmware update      | carrier fs ota <identity> ota firmware.img        |
| /v0/reboot                       | reboot system        | carrier stream <identity> /v0/reboot              |
| /v0/sft                          | file transfer        | carrier fs push <identity> /localfile /remotefile |
| /v0/shell                        | shell                | carrier shell <identity>                          |
| /v2/captif.proximity.v1/scan     | proximity            | see proximity documentation                       |
| /v2/captif.proximity.v1/count    | proximity            | see proximity documentation                       |
| /v2/captif/sta_block             | station bans         | see  sta_block documentation                      |
| /v2/carrier.sysinfo.v1/netsurvey | network discovery    | carrier netsurvey <identity>                      |
| /v2/carrier.sysinfo.v1/sysinfo   | system information   | carrier sysinfo <identity>                        |
| /v2/genesis.v1                   | system configuration | carrier genesis <identity>                        |




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
carrier get oWpiPNBufRxmvNM3aK7opXXzjRHkyq2kXWnCNUu9JZFatNX /v2/captif/sta_block -H time 10000 -H addr 80:b1:15:92:22:06 -H interface publicap
```



### genesis

see https://github.com/devguardio/genesis
