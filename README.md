## Icinga Command

```
object CheckCommand "check_synology" {
    import "plugin-check-command"
    command = [ PluginDir + "/check_synology.py" ]
    timeout = 45s
    arguments += {
        "--auth_prot" = {
            description = "SNMPv3 - authentication protocol"
            value = "$snmpv3_auth_proto$"
        }
        "--disk_temp_crit" = {
            description = "Disk - critical temperature (in °C)"
            value = "$disk_temp_crit$"
        }
        "--disk_temp_warn" = {
            description = "Disk - warning temperature (in °C)"
            value = "$disk_temp_warn$"
        }
        "--memory_crit" = {
            description = "Memory - critical utilization (in percent)"
            value = "$mem_critical$"
        }
        "--memory_warn" = {
            description = "Memory - warning utilization (in percent)"
            value = "$mem_critical$"
        }
        "--net_crit" = {
            description = "Network - critical utilization (in percent)"
            value = "$network_warn$"
        }
        "--net_warn" = {
            description = "Network - warning utilization (in percent)"
            value = "$network_crit$"
        }
        "--port" = {
            description = "SNMP port"
            value = "$snmp_port$"
        }
        "--priv_prot" = {
            description = "SNMPv3 - privacy (encryption) protocol"
            value = "$snmpv3_priv_proto$"
        }
        "--storage_used_crit" = {
            description = "Storage - critical usage (in percent)"
            value = "$storage_used_warn$"
        }
        "--storage_used_warn" = {
            description = "Storage - warning usage (in percent)"
            value = "$storage_used_warn$"
        }
        "--temp_crit" = {
            description = "Status - critical NAS temperature (in °C)"
            value = "$temp_crit$"
        }
        "--temp_warn" = {
            description = "Status - warning NAS temperature (in °C)"
            value = "$temp_warn$"
        }
        "--ups_level_crit" = {
            description = "UPS - critical battery level (in percent)"
            value = "$ups_level_crit$"
        }
        "--ups_level_warn" = {
            description = "UPS - warning battery level (in percent)"
            value = "$ups_level_warn$"
        }
        "--ups_load_crit" = {
            description = "UPS - critical load (in percent)"
            value = "$ups_load_crit$"
        }
        "--ups_load_warn" = {
            description = "UPS - warning load (in percent)"
            value = "$ups_load_crit$"
        }
        "-C" = {
            description = "SNMPv1/2 - community"
            value = "$snmp_community_name$"
        }
        "-H" = {
            description = "SNMP host"
            value = "$snmpv3_address$"
        }
        "-a" = {
            description = "SNMPv3 - authentication key"
            value = "$snmpv3_auth_key$"
        }
        "-c" = {
            description = "Load - number of cpu cores for calculating thresholds"
            value = "$cpu_cores$"
        }
        "-m" = {
            description = "mode - selected measurements - load,memory, disk, raid, storage, ups, status, update, all (comma-seperated list)"
            value = "$synology_mode$"
        }
        "-p" = {
            description = "SNMPv3 - privacy key"
            value = "$snmpv3_priv_key$"
        }
        "-u" = {
            description = "SNMPv3 - username"
            value = "$snmpv3_user$"
        }
        "-v" = {
            description = "SNMP version"
            value = "$snmp_version$"
        }
        "-x" = {
            description = "mode - excluded measurements - load,memory, disk, raid, storage, ups, status, update (comma-seperated list)"
            value = "$synology_exclude_mode$"
        }
    }
    vars.disk_temp_crit = "70"
    vars.disk_temp_warn = "60"
    vars.mem_critical = "90"
    vars.mem_warning = "80"
    vars.network_crit = "95"
    vars.network_warn = "90"
    vars.snmp_port = "161"
    vars.snmp_version = "3"
    vars.snmpv3_address = "$host.address$"
    vars.snmpv3_auth_proto = "SHA"
    vars.snmpv3_priv_proto = "AES"
    vars.storage_used_crit = "90"
    vars.storage_used_warn = "80"
    vars.synology_mode = "all"
    vars.temp_crit = "80"
    vars.temp_warn = "70"
    vars.ups_level_crit = "50"
    vars.ups_level_warn = "25"
    vars.ups_load_crit = "90"
    vars.ups_load_warn = "80"
}
```

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
| -C | SNMPv1/2 - community| string | *public* | YES (for SNMPv1/2) |
| -m | mode - selected measurements | *load,memory, disk, raid, storage, ups, status, update, all* (comma-seperated list) | *all* | None |
| -x | mode - excluded measurements | *load,memory, disk, raid, storage, ups, status, update* (comma-seperated list) | None | None |
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
