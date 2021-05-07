## Arguments

| Argument | Description | Possible values | Default | Mandatory |
| ------ | ------ | ------ | ------ | ------ |
| -H | SNMP host | hostname/ip-address | None | YES |
| -v | SNMP version | *1/2c/3* | *3* | NO |
| --port | SNMP port | int | *161* | NO |
| -u | SNMPv3 - username | string | None | YES (for SNMPv3) |
| --auth_prot | SNMPv3 - authentication protocol | *SHA/MD5* | *SHA* | NO |
| --priv_prot | SNMPv3 - privacy (encryption) protocol | *AES/DES* | *AES* | NO |
| -a | SNMPv3 - authentication key | string | None | YES (for SNMPv3) |
| -p | SNMPv3 - privacy key| string | None | YES (for SNMPv3) |
| -C | SNMPv1/2 - community| string | None | YES (for SNMPv1/2) |
| -m | mode - selected measurements | *load,memory,disk,raid,storage,ups,status,update,all* (comma-seperated list) | *all* | None |
| -x | mode - excluded measurements | *load,memory,disk,raid,storage,ups,status,update* (comma-seperated list) | None | None |
| -c | Load - number of cpu cores for calculating thresholds | int | *4* | None |
| --memory_warn | Memory - warning utilization (in percent) | int | *80* | None |
| --memory_crit | Memory - critical utilization (in percent) | int | *90* | None |
| --net_warn | Network - warning utilization (in percent) | int | *90* | None |
| --net_crit | Network - critical utilization (in percent) | int | *95* | None |
| --temp_warn | Status - warning NAS temperature (in °C) | int | *60* | None |
| --temp_crit | Status - critical NAS temperature (in °C) | int | *80* | None |
| --disk_temp_warn | Disk - warning temperature (in °C) | int | *50* | None |
| --disk_temp_crit | Disk - critical temperature (in °C) | int | *70* | None |
| --storage_used_warn | Storage - warning usage (in percent) | int | *80* | None |
| --storage_used_crit | Storage - critical usage (in percent) | int | *90* | None |
| --ups_level_warn | UPS - warning battery level (in percent) | int | *50* | None |
| --ups_level_crit | UPS - critical battery level (in percent) | int | *30* | None |
| --ups_load_warn | UPS - warning load (in percent) | int | *80* | None |
| --ups_load_crit | UPS - critical load (in percent) | int | *90* | None |
