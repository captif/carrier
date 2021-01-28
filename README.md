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
| /v2/captif.proximity.v1/scan     | proximity            | see proximity documentation                       |
| /v2/captif.proximity.v1/count    | proximity            | see proximity documentation                       |
| /v2/captif/sta_block             | station bans         | see sta_block documentation                       |




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
