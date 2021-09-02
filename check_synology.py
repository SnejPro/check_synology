#!/usr/bin/python3
import argparse
import sys
import math
import re
import os
import time
import subprocess
import json
from pprint import pprint

AUTHOR = "SnejPro"
VERSION = 0.1

parser = argparse.ArgumentParser()
parser.add_argument("-H", dest="hostname", help="Hostname/IP-adress", type=str)
parser.add_argument("-v", dest="version", help="SNMP version", type=str, default='3', choices=["1","2c","3"])
parser.add_argument("--port", dest="port", help="SNMP oirt", type=int, default=161)

parser.add_argument("-u", dest="username", help="SNMPv3 - username", type=str)
parser.add_argument("--auth_prot", help="SNMPv3 - authentication protocol", type=str, default="SHA", choices=["MD5", "SHA", "None"])
parser.add_argument("--priv_prot", help="SNMPv3 - privacy (encryption) protocol", type=str, default="AES", choices=["DES", "AES", "None"])
parser.add_argument("-a", dest="auth_key", help="SNMPv3 - authentication key", type=str)
parser.add_argument("-p", dest="priv_key", help="SNMPv3 - privacy key", type=str)
parser.add_argument("-C", dest="community", help="SNMP v1, v2c - community", default="public", type=str)

parser.add_argument("-m", dest="mode", help="Comma-seperated list of modes that should be checked: load,memory,disk,raid,storage,ups,status,update,all", type=str, default='all')
parser.add_argument("-x", dest="exclude_mode", help="Comma-seperated list of modes that should not be checked", type=str)

parser.add_argument("-c", dest="cpu", help="Load - number of cpu cores for calculating thresholds", type=int, default=4)
parser.add_argument("--memory_warn", help="Memory - warning utilization (percent)", type=int, default=80)
parser.add_argument("--memory_crit", help="Memory - critical utilization (percent)", type=int, default=90)
parser.add_argument("--net_warn", help="Network - warning utilization (percent of linkspeed)", type=int, default=90)
parser.add_argument("--net_crit", help="Network - critical utilization (percent of linkspeed)", type=int, default=95)
parser.add_argument("--temp_warn", help="Status - warning NAS temperature", type=int, default=60)
parser.add_argument("--temp_crit", help="Status - critical NAS temperature", type=int, default=80)
parser.add_argument("--disk_temp_warn", help="Disk - warning temperature", type=int, default=50)
parser.add_argument("--disk_temp_crit", help="Disk - critical temperature", type=int, default=70)
parser.add_argument("--storage_used_warn", help="Storage - warning usage (percent)", type=int, default=80)
parser.add_argument("--storage_used_crit", help="Storage - critical usage (percent)", type=int, default=90)
parser.add_argument("--ups_level_warn", help="UPS - warning battery level (percent)", type=int, default=50)
parser.add_argument("--ups_level_crit", help="UPS - critical battery level (percent)", type=int, default=30)
parser.add_argument("--ups_load_warn", help="UPS - warning load (percent)", type=int, default=80)
parser.add_argument("--ups_load_crit", help="UPS - critical load (percent)", type=int, default=90)
parser.add_argument("--net_aliases", help="", type=str, default="")
args = parser.parse_args()

returnstring = ""
returnperf = " |"
state = "OK"

timeout=5

netfilename = "/tmp/check_synology_"+args.hostname+".json"

session_kargs=[
    "-O","q",
    "-v",str(args.version),
]

net_alias = {}
if args.net_aliases != '':
    nets = x = args.net_aliases.split(",")
    for v in nets:
        net=v.split("=")
        net_alias[net[0]] = net[1]

if args.version == '3':
    if args.auth_prot == "None":
        session_kargs.append("-l")
        session_kargs.append("noAuthNoPriv")
    elif args.priv_prot == "None":
        session_kargs.append("-l")
        session_kargs.append("authNoPriv")
        
        session_kargs.append("-a")
        session_kargs.append(args.auth_prot)
        
        session_kargs.append("-A")
        session_kargs.append(args.auth_key)
        
        session_kargs.append("-u")
        session_kargs.append(args.username)
    else:
        session_kargs.append("-l")
        session_kargs.append("authPriv")
        
        session_kargs.append("-a")
        session_kargs.append(args.auth_prot)
        
        session_kargs.append("-A")
        session_kargs.append(args.auth_key)
        
        session_kargs.append("-u")
        session_kargs.append(args.username)

        session_kargs.append("-x")
        session_kargs.append(args.priv_prot)
        
        session_kargs.append("-X")
        session_kargs.append(args.priv_key)
else:
    session_kargs.append("-c")
    session_kargs.append(args.community)    

session_kargs.append(args.hostname+":"+str(args.port))

def proc(com, oids):
    command = [com]
    for a in session_kargs:
        command.append(a)
    if isinstance(oids, list):
        for o in oids:
            command.append(o)
    else:
        command.append(oids)
    result=subprocess.run(command, capture_output=True).stdout.decode('UTF-8')
    lines = result.split("\n")
    results = {}
    for l in lines:
        if l != "":
            key=re.findall("(iso(\.[0-9]+)+) ", l)[0][0]
            key=key.replace("iso", "1")
            value=re.findall("(?<= ).+", re.findall(" .+", l)[0])[0]
            extractval=re.findall('(?<=^").*(?="$)',value)
            if len(extractval)!=0:
                value=extractval[0]
            results[key]=value
    return results

def proc_snmpwalk(oid):
    command = "snmpwalk"
    return proc(command, oid)

def proc_snmpget(oids):
    command = "snmpget"
    return proc(command, oids)

cpu_cores = args.cpu
temp_warn = args.temp_warn
temp_crit = args.temp_crit

memory_warn = args.memory_warn
memory_crit = args.memory_crit

storage_used_warn = args.storage_used_warn
storage_used_crit = args.storage_used_crit

disk_temp_warn = args.disk_temp_warn
disk_temp_crit = args.disk_temp_crit

net_warn = args.net_warn
net_crit = args.net_crit

ups_level_warn = args.ups_level_warn
ups_level_crit = args.ups_level_crit
ups_load_warn = args.ups_load_warn
ups_load_crit = args.ups_load_crit

if args.mode != 'all':
    mode = re.findall("[a-z]+", args.mode)
else:
    mode = args.mode
 
if args.exclude_mode != None:
    exclude_mode = re.findall("[a-z]+", args.exclude_mode)
else:
    exclude_mode = []

network_mesurement_time = 5
state = 'OK'

def add_queue(oid, name, tag, check=False, warn=None, crit=None, perf=False, inv=False):
    element = {
        "tag": tag,
        "name": name,
        "perf": perf,
        "inv": inv,
        "check": check
    }
    if warn != None:
        element["warn"]=warn
    if crit != None:
        element["crit"]=crit 
 
    queue[oid]=element

def format_bytes(size):
    # 2**10 = 1024
    #power = 2**10
    power = 10**3
    n = 0
    power_labels = {0 : '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    while size > power:
        size /= power
        n += 1
    return size, power_labels[n]+'B', str(round(size,2))+' '+power_labels[n]+'B'


def get_queue_oids():
    oids = []
    for k, v in queue.items():
        oids.append(ObjectType(ObjectIdentity(k)))
    return oids;
    
def snmpwalk(oid):
    result={}
    snmpres = proc_snmpwalk(oid)
    return snmpres

def snmpget(oid):
    oids = []
    if isinstance(oid, dict):
        for k in oid:
            oids.append(k)
    else:
        oids = oid
    result={}
    snmpres = proc_snmpget(oids)
    return snmpres
            
def change_state(locstate):
    global state
    if locstate != "OK" and state != "CRITICAL":
        if locstate == "WARNING":
            state = "WARNING"
        elif locstate == "CRITICAL":
            state = "CRITICAL"
    
def check_standard(value, warn, crit, inv=False):
    if inv==False:
        if crit > value >= warn:
            locstate = "WARNING"
        elif value >= crit:
            locstate = "CRITICAL"
        else:
            locstate = "OK"
    else:
        if crit < value <= warn:
            locstate = "WARNING"
        elif value <= crit:
            locstate = "CRITICAL"
        else:
            locstate = "OK"
    
    change_state(locstate)  
    return locstate
 
def check_ups_status(value):
    if value == "OL":
        locstate = "OK"
    elif value == "OL CHRG":
        locstate = "WARNING"
    else:
        locstate = "CRITICAL"
    
    change_state(locstate)  
    return locstate

def check_failed(value):
    if value == "1":
        locstate = "OK"
        output = "Normal"
    elif value == "2":
        locstate = "Critical"
        output = "Failed"
        
    change_state(locstate)  
    return output+' - '+locstate
    
def check_update(value):
    if value == "1":
        locstate = "WARNING"
        output = "Available"
    elif value == "2":
        locstate = "OK"
        output = "Unavailable"
    elif value == "3":
        locstate = "WARNING"
        output = "Connecting"
    elif value == "4":
        locstate = "WARNING"
        output = "Disconnected"
    elif value == "5":
        locstate = "CRITICAL"
        output = "Others"
        
    change_state(locstate)  
    return output+' - '+locstate
    
def check_disk_status(value):
    if value == "1":
        locstate = "OK"
        output = "Normal"
    elif value == "2":
        locstate = "WARNING"
        output = "Initialized"
    elif value == "3":
        locstate = "WARNING"
        output = "NotInitialized"
    elif value == "4":
        locstate = "CRITICAL"
        output = "SystemPartitionFailed"
    elif value == "5":
        locstate = "CRITICAL"
        output = "Crashed"
        
    change_state(locstate)  
    return output+' - '+locstate
   
def check_raid_status(value):
    if value == "1":
        locstate = "OK"
        output = "Normal"
    elif value == "2":
        locstate = "WARNING"
        output = "Repairing"
    elif value == "3":
        locstate = "WARNING"
        output = "Migrating"
    elif value == "4":
        locstate = "WARNING"
        output = "Expanding"
    elif value == "5":
        locstate = "WARNING"
        output = "Deleting"
    if value == "6":
        locstate = "WARNING"
        output = "Creating"
    elif value == "7":
        locstate = "OK"
        output = "RaidSyncing"
    elif value == "8":
        locstate = "OK"
        output = "RaidParityChecking"
    elif value == "9":
        locstate = "WARNING"
        output = "RaidAssembling"
    elif value == "10":
        locstate = "WARNING"
        output = "Canceling"
    if value == "11":
        locstate = "CRITICAL"
        output = "Degrade"
    elif value == "12":
        locstate = "CRITICAL"
        output = "Crashed"
    elif value == "13":
        locstate = "WARNING"
        output = "DataScrubbing"
    elif value == "14":
        locstate = "WARNING"
        output = "RaidDeploying"
    elif value == "15":
        locstate = "WARNING"
        output = "RaidUnDeploying"
    elif value == "16":
        locstate = "WARNING"
        output = "RaidMountCache"
    elif value == "17":
        locstate = "WARNING"
        output = "RaidUnmountCache"
    elif value == "18":
        locstate = "WARNING"
        output = "RaidExpandingUnfinishedSHR"
    elif value == "19":
        locstate = "WARNING"
        output = "RaidConvertSHRToPool"
    elif value == "20":
        locstate = "WARNING"
        output = "RaidMigrateSHR1ToSHR2"
    elif value == "21":
        locstate = "CRITICAL"
        output = "RaidUnknownStatus"
        
    change_state(locstate)  
    return output+' - '+locstate   

def render(r, unit=''):
    global returnstring
    global returnperf
    for k, v in r.items():
  
        if v["check"]!=False and "warn" in v:
            check_result = globals()[v["check"]](float(v["value"]), float(v["warn"]), float(v["crit"]), v["inv"])
        elif v["check"]!=False:
            check_result = globals()[v["check"]](v["value"])
        
        pv = {}
        if unit=='B':
            pv["value"] = format_bytes(v["value"])[2]
            v["value"] = str(v["value"])+'B'
            if v["check"]!=False and "warn" in v:
                pv["warn"] = format_bytes(v["warn"])[2]
                pv["crit"] = format_bytes(v["crit"])[2]
                v["warn"] = str(v["warn"])
                v["crit"] = str(v["crit"])
        else:
            pv["value"] = v["value"]
            if v["check"]!=False and "warn" in v:
                pv["warn"] = v["warn"]
                pv["crit"] = v["crit"]
        
        returnstring += "\n"+v["name"]+": "+str(pv["value"])
        if v["check"]!=False:
            returnstring += ' - '+check_result
        if v["perf"] == True:
            if "warn" in v:
                returnperf += " "+v["tag"]+"="+str(v["value"])+";"+str(v["warn"])+";"+str(v["crit"])
            else:
                returnperf += " "+v["tag"]+"="+str(v["value"])

def render_storage(r, inv=False):
    global returnstring
    global returnperf
    id = num
    size_bytes = int(r['1.3.6.1.2.1.25.2.3.1.4.'+id]['value'])*int(r['1.3.6.1.2.1.25.2.3.1.5.'+id]['value'])
    used_bytes = int(r['1.3.6.1.2.1.25.2.3.1.4.'+id]['value'])*int(r['1.3.6.1.2.1.25.2.3.1.6.'+id]['value'])
    used_percent = (used_bytes/size_bytes)*100
    #Name
    returnstring += "\n"+r['1.3.6.1.2.1.25.2.3.1.3.'+id]['name']+": "+r['1.3.6.1.2.1.25.2.3.1.3.'+id]['value']
    #Allocation Units
    returnstring += "\n"+r['1.3.6.1.2.1.25.2.3.1.4.'+id]['name']+": "+r['1.3.6.1.2.1.25.2.3.1.4.'+id]['value']
    #Size
    returnstring += "\n"+r['1.3.6.1.2.1.25.2.3.1.5.'+id]['name']+": "+str(round(format_bytes(size_bytes)[0], 2))+" "+format_bytes(size_bytes)[1]
    #Used
    crit = r['1.3.6.1.2.1.25.2.3.1.6.'+id]['crit']
    warn = r['1.3.6.1.2.1.25.2.3.1.6.'+id]['warn']
    if inv==False:
        if crit > used_percent >= warn:
            locstate = "WARNING"
        elif used_percent >= crit:
            locstate = "CRITICAL"
        else:
            locstate = "OK"
    else:
        if crit < used_percent <= warn:
            locstate = "WARNING"
        elif used_percent <= crit:
            locstate = "CRITICAL"
        else:
            locstate = "OK"
    returnstring += "\n"+r['1.3.6.1.2.1.25.2.3.1.6.'+id]['name']+": "+str(round(format_bytes(used_bytes)[0], 2))+" "+format_bytes(used_bytes)[1]+" - "+str(round(used_percent, 2))+"% - "+locstate
    returnperf += " "+r['1.3.6.1.2.1.25.2.3.1.6.'+id]['tag']+"="+str(round(used_bytes))+"B;"+str(round(size_bytes/100*warn))+";"+str(round(size_bytes/100*crit))+";0;"+str(size_bytes)
    change_state(locstate)
    
def merge(res):
    for k, v in res.items():
        queue[k]["value"] = v

def exitCode():
    if state == 'OK':
        sys.exit(0)
    if state == 'WARNING':
        sys.exit(1)
    if state == 'CRITICAL':
        sys.exit(2)
    if state == 'UNKNOWN':
        sys.exit(3)

if ('load' in mode or mode == 'all') and 'load' not in exclude_mode:
    returnstring += "\n\nLoad:"
    queue = {}
    queue['1.3.6.1.4.1.2021.10.1.3.1'] = { "name": 'Load - 1', "tag": 'load-1', "check": "check_standard", "warn": cpu_cores*2, "crit": cpu_cores*4, "perf": True, "inv": False, }
    queue['1.3.6.1.4.1.2021.10.1.3.2'] = { "name": 'Load - 5', "tag": 'load-5', "check": "check_standard", "warn": cpu_cores*1.5, "crit": cpu_cores*2, "perf": True, "inv": False, }
    queue['1.3.6.1.4.1.2021.10.1.3.3'] = { "name": 'Load - 15', "tag": 'load-15', "check": "check_standard", "warn": cpu_cores-0.3, "crit": cpu_cores, "perf": True, "inv": False, }
    res = snmpget(queue)
    merge(res)
    render(queue)

if ('memory' in mode or mode == 'all') and 'memory' not in exclude_mode:
    returnstring += "\n\nMemory:"
    queue = {}
    
    queue['1.3.6.1.4.1.2021.4.5.0'] = { "name": 'Memory - Total', "tag": 'memory-total', "check": False, "perf": True, "inv": False, }
    queue['1.3.6.1.4.1.2021.4.6.0'] = { "name": 'Memory - Used', "tag": 'memory-used', "check": "check_standard", "perf": True, "inv": False, }
    queue['1.3.6.1.4.1.2021.4.15.0'] = { "name": 'Memory - Cached', "tag": 'memory-cached', "check": False, "perf": True, "inv": False, }

    res = snmpget(queue)
    merge(res)
    for k, v in queue.items():
        v["value"] = int(v["value"])*1024
    queue['1.3.6.1.4.1.2021.4.6.0']['warn'] = round(int(queue['1.3.6.1.4.1.2021.4.5.0']['value'])*memory_warn/100)
    queue['1.3.6.1.4.1.2021.4.6.0']['crit'] = round(int(queue['1.3.6.1.4.1.2021.4.5.0']['value'])*memory_crit/100)
    render(queue, unit='B')

if ('disk' in mode  or mode == 'all') and 'disk' not in exclude_mode:
    returnstring += "\n\nDisks:"
    disks = snmpwalk('1.3.6.1.4.1.6574.2.1.1.2');
    for k, v in disks.items():
        queue = {}
        num = re.findall("[0-9]+$", k)[0]
        queue['1.3.6.1.4.1.6574.2.1.1.2.'+str(num)] = { "name": 'Disk '+str(num)+' - Name', "tag": 'disk-'+str(num)+'-name', "check": False, "perf": False, "inv": False, }
        queue['1.3.6.1.4.1.6574.2.1.1.5.'+str(num)] = { "name": 'Disk '+str(num)+' - Status', "tag": 'disk-'+str(num)+'-status', "check": "check_disk_status", "perf": False, "inv": False }
        queue['1.3.6.1.4.1.6574.2.1.1.3.'+str(num)] = { "name": 'Disk '+str(num)+' - Model', "tag": 'disk-'+str(num)+'-model', "check": False, "perf": False, "inv": False, }
        queue['1.3.6.1.4.1.6574.2.1.1.6.'+str(num)] = { "name": 'Disk '+str(num)+' - Temperature', "tag": 'disk-'+str(num)+'-temperature', "check": "check_standard", "warn": disk_temp_warn, "crit": disk_temp_crit, "perf": True, "inv": False, }

        res = snmpget(queue)
        merge(res)
        render(queue)

if ('storage' in mode  or mode == 'all') and 'storage' not in exclude_mode:
    returnstring += "\n\nStorages:"
    queue = {}
    storages = snmpwalk('1.3.6.1.2.1.25.2.3.1.3');
    storage_ids = []
    for k, v in storages.items():
        storageid = k
        storagename = v
        x = re.search("\/volume[0-9]*", storagename)
        if x != None:
            storage_ids.append(re.findall("[0-9]+$", storageid)[0])
    for num in storage_ids:
        queue['1.3.6.1.2.1.25.2.3.1.3.'+str(num)] = { "name": 'Storage '+str(num)+' - Name', "tag": 'storage-'+str(num)+'-name', "check": False, "perf": False, "inv": False, }
        queue['1.3.6.1.2.1.25.2.3.1.4.'+str(num)] = { "name": 'Storage '+str(num)+' - Allocations Units', "tag": 'storage-'+str(num)+'-alloc-units', "check": False, "perf": False, "inv": False, }
        queue['1.3.6.1.2.1.25.2.3.1.5.'+str(num)] = { "name": 'Storage '+str(num)+' - Size', "tag": 'storage-'+str(num)+'-size', "check": False, "perf": True, "inv": False, }
        queue['1.3.6.1.2.1.25.2.3.1.6.'+str(num)] = { "name": 'Storage '+str(num)+' - Used', "tag": 'storage-'+str(num)+'-used', "check": "check_storage", "warn":storage_used_warn, "crit":storage_used_crit,"perf": True, "inv": False, }
        
        res = snmpget(queue)
        merge(res)
        render_storage(queue)

if ('raid' in mode  or mode == 'all') and 'raid' not in exclude_mode:
    returnstring += "\n\nRaids:"
    queue = {}
    raids = snmpwalk('1.3.6.1.4.1.6574.3.1.1.2');
    for k, v in raids.items():
        num = re.findall("[0-9]+$", k)[0]    
        queue['1.3.6.1.4.1.6574.3.1.1.2.'+str(num)] = { "name": 'RAID '+str(num)+' - Name', "tag": 'raid-'+str(num)+'-name', "check": False, "perf": False, "inv": False, }
        queue['1.3.6.1.4.1.6574.3.1.1.3.'+str(num)] = { "name": 'RAID '+str(num)+' - Status', "tag": 'raid-'+str(num)+'-status', "check": "check_raid_status", "perf": False, "inv": False, }

    res = snmpget(queue)
    merge(res)
    render(queue)

if ('update' in mode  or mode == 'all') and 'update' not in exclude_mode:
    returnstring += "\n\nUpdate:"
    queue = {}
    
    queue['1.3.6.1.4.1.6574.1.5.4.0'] = { "name": 'Update - Status', "tag": 'update-status', "check": "check_update", "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.5.3.0'] = { "name": 'Update - DSM-Version', "tag": 'update-version', "check": False, "perf": False, "inv": False, }
    
    res = snmpget(queue)
    merge(res)
    render(queue)

if ('status' in mode  or mode == 'all') and 'status' not in exclude_mode:
    returnstring += "\n\nStatus:"
    queue = {}
    
    queue['1.3.6.1.4.1.6574.1.5.1.0'] = { "name": 'Status - Model', "tag": 'status-model', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.5.2.0'] = { "name": 'Status - S/N', "tag": 'status-serial', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.2.0'] = { "name": 'Status - Temperature', "tag": 'status-temp', "check": "check_standard", "warn":temp_warn, "crit":temp_crit,"perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.1.0'] = { "name": 'Status - System', "tag": 'status-system', "check": "check_failed", "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.4.1.0'] = { "name": 'Status - System Fan', "tag": 'status-fan-system', "check": "check_failed", "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.4.2.0'] = { "name": 'Status - CPU Fan', "tag": 'status-fan-cpu', "check": "check_failed", "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.1.3.0'] = { "name": 'Status - Power', "tag": 'status-power', "check": "check_failed", "perf": False, "inv": False, }
    
    res = snmpget(queue)
    merge(res)
    render(queue)

if ('ups' in mode  or mode == 'all') and 'ups' not in exclude_mode:
    returnstring += "\n\nUPS:"
    queue = {}
    
    queue['1.3.6.1.4.1.6574.4.1.1.0'] = { "name": 'UPS Model', "tag": 'ups-model', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.1.2.0'] = { "name": 'UPS Manufacturer', "tag": 'ups-manufacturer', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.1.3.0'] = { "name": 'UPS S/N', "tag": 'ups-serial', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.2.1.0'] = { "name": 'UPS Status', "tag": 'ups-status', "check": "check_ups_status", "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.2.6.2.0'] = { "name": 'UPS Manufacturer-Date', "tag": 'ups-manufacturer-date', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.2.12.1.0'] = { "name": 'UPS Load', "tag": 'ups-load', "check": "check_standard", "warn": ups_load_warn, "crit": ups_load_crit,"perf": True, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.3.1.1.0'] = { "name": 'UPS Battery Level', "tag": 'ups-battery-level', "check": "check_standard", "warn": ups_level_warn, "crit": ups_level_crit,"perf": True, "inv": True, }
    queue['1.3.6.1.4.1.6574.4.3.1.4.0'] = { "name": 'UPS Battery Warning Level', "tag": 'ups-warning-battery-level', "check": False, "perf": False, "inv": False, }
    queue['1.3.6.1.4.1.6574.4.3.12.0'] = { "name": 'UPS Battery Type', "tag": 'ups-battery-type', "check": False, "perf": False, "inv": False, }

    res = snmpget(queue)
    if res['1.3.6.1.4.1.6574.4.1.1.0'] != 'No Such Instance currently exists at this OID':
        merge(res)
        render(queue)
    else:
        returnstring += " No UPS found"

if ('network' in mode or mode == 'all') and 'network' not in exclude_mode:
    networks = snmpwalk('1.3.6.1.2.1.31.1.1.1.1')
    network_speeds = snmpwalk('1.3.6.1.2.1.31.1.1.1.15')
    networks_connected = []
    returnstring += "\n\nNetwork:"
    
    networks_downlink1 = snmpwalk('1.3.6.1.2.1.31.1.1.1.6')
    networks_uplink1 = snmpwalk('1.3.6.1.2.1.31.1.1.1.10')
    networks_time1 = time.time()
    networks_json = {}
    if os.path.exists(netfilename):
        jsonfile = open(netfilename, "r")
        jsoncontent = jsonfile.read()
        try:
            networks_old=json.loads(jsoncontent)
        except:
            networks_old=False
    else:
        networks_old=False
 
    for k, v in networks.items():
        network = {}
        #if re.search("^eth[0-9]+", v) != None:
        network["id"] = re.findall("[0-9]+$", k)[0]
        
        network["name"] = v
        if v in net_alias:
            network["alias"] = net_alias[v]+"("+v+")"
        else:
            network["alias"] = v
            
        if network_speeds['1.3.6.1.2.1.31.1.1.1.15.'+network["id"]] != '0':
            network["link_speed"] = int(network_speeds['1.3.6.1.2.1.31.1.1.1.15.'+network["id"]])*10**6
            networks_connected.append(network)

    for n in networks_connected:
        networks_json[n["name"]] = {
            "downlink_counter": int(networks_downlink1['1.3.6.1.2.1.31.1.1.1.6.'+n["id"]]),
            "uplink_counter": int(networks_uplink1['1.3.6.1.2.1.31.1.1.1.10.'+n["id"]]),
            "time": networks_time1
        }
        if networks_old != False and n["name"] in networks_old:
            returnstring += "\n"+n["alias"]+":"
            n["net_warn"]=round(n["link_speed"]*net_warn/100)
            n["net_crit"]=round(n["link_speed"]*net_crit/100)
        
            timespan = networks_time1-networks_old[n["name"]]["time"]
        
            n["downlink1"]=int(networks_old[n["name"]]["downlink_counter"])
            n["downlink2"]=int(networks_downlink1['1.3.6.1.2.1.31.1.1.1.6.'+n["id"]])
            n["downlink_speed"]=round(((n["downlink2"]-n["downlink1"])*8)/timespan)
            downlink_speed_check = check_standard(n["downlink_speed"],n["link_speed"]*n["net_warn"],n["net_crit"])
            returnstring += "\nDownlink: "+str(n["downlink_speed"])+"b/s - "+downlink_speed_check
            returnperf += " '"+n["alias"]+"_downlink_speed'="+str(n["downlink_speed"]/8)+"B;"+str(n["net_warn"]/8)+";"+str(n["net_crit"]/8)
            returnperf += " '"+n["alias"]+"_downlink_octects'="+str(n["downlink2"])
            
            n["uplink1"]=int(networks_old[n["name"]]["uplink_counter"])
            n["uplink2"]=int(networks_uplink1['1.3.6.1.2.1.31.1.1.1.10.'+n["id"]])
            n["uplink_speed"]=round(((n["uplink2"]-n["uplink1"])*8)/timespan)
            uplink_speed_check = check_standard(n["uplink_speed"],n["net_warn"],n["net_crit"])
            returnstring += "\nUplink: "+str(n["uplink_speed"])+"b/s - "+uplink_speed_check
            returnperf += " '"+n["alias"]+"_uplink_speed'="+str(n["uplink_speed"]/8)+"B;"+str(n["net_warn"]/8)+";"+str(n["net_crit"]/8)
            returnperf += " '"+n["alias"]+"_uplink_octects'="+str(n["uplink2"])

    jsonfile = open(netfilename, "w")
    jsonfile.write(json.dumps(networks_json))
    jsonfile.close()    


print("NAS-Status: "+state+returnstring+returnperf)
exitCode()
