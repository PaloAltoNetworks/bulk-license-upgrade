#!/usr/bin/python3

# READ ME
# Built in modules being used: os, time, logging, argparse, json, collections
# New modules required: tabulate (inorder to show summary)

# Pre-requisites
# 1. Install latest python3 and the required modules as per above on your execution server. Make sure all the firewalls are reachable from this server.
# 1. Create a dummy username and password on each FW with admin preveliges. This can be done from Panorama. Steps refer here
# 2. Obtain the licensing API key from CSP account. Steps here. Add it to license_api_key.txt in the same folder.
# 3. Obtain the deployment profile from CSP for the FLEX license. Repeat this script for each deployment profile separately.
# 4. Provide the list of the FW IPs which need to be migrated to Flex license. Add it to firewall_ips.txt in the same folder. Provide one IP per line, no additional info. Refer to sample here.
# 5. Trigger the script using the below commands.
# 6. Grab a cup of coffee while we migrate your firewalls to FW-FLEX license.

import os
import time
import logging
import argparse
import json
from tabulate import tabulate
from collections import Counter

# Argument Parsing
parser = argparse.ArgumentParser()
parser.add_argument( '-input',required=True,help='Provide input filename which has credential details, refer sample.json')
parser.add_argument( '-iplist',required=True,help='Provide input file with all FW IPs (One IP per line)')
parser.add_argument( '-action',required=True,help='Provide,\
                                                   \ngetcores - to get the count of FWs with x cores.\
                                                   \ngetstatus - to get the current license on each FW.\
                                                   \nupgrade - to trigger upgrade for each FW.')
parser.add_argument( '-log','--loglevel',default='info', help='Provide -log debug and retry for the IPs that run into issue' )
args = parser.parse_args()
logging.basicConfig(format='%(asctime)-26s %(levelname)-8s %(message)s',level=args.loglevel.upper())
#logging.basicConfig(format='%(asctime)s %(levelname)-8s',level=args.loglevel.upper())

# Reading user inputs for login and upgrade
fname=args.input
f = open(fname)
userdata = json.load(f)
username = userdata.get('username','admin')
password = userdata.get('password','password')
license_api_key = userdata.get('license_api_key','abcd1234')
dp_auth_code = userdata.get('dp_auth_code','AUTHCODE')

waittime = 600 #Secs to wait before checking the upgrade status
upgsleep = 10

# Reading user input of FW IPs to be upgraded
iname=args.iplist
fw_list = open(iname,'r').readlines()
fw_list = [f.strip("\n\r ") for f in fw_list] 
logging.debug(f"List of FWs to be upgraded:\n{fw_list}\n")

action = args.action

sys_info = {}
sys_info_before_upg = {}
sys_info_after_upg = {}
fw_api_keys = {}
new_lics = {}
old_lics = {}
coredict = {}


def connect_fw(fw_ip,username,password):
    # Get FW API key
    try:
        args1 = "'Content-Type: application/x-www-form-urlencoded'"
        args2 = '--connect-timeout 5 --max-time 50 --retry 3 --retry-delay 3 --retry-max-time 50 -s -k'
        cmd = f"curl -H {args1} {args2} -X POST https://{fw_ip}/api/?type=keygen -d 'user={username}&password={password}'"
        fw_out1 = os.popen(cmd)
        logging.debug(f"{fw_ip}: FW connection out:{fw_out1}")
        fw_out = fw_out1.read()

        logging.debug(f"{fw_ip}: FW API key query output:{fw_out}**")
        if not fw_out:
            logging.error(f"{fw_ip}: Connection FAILED. API key CANNOT be obtained")
            logging.debug(f"{fw_ip}: FW connectivity failed. Error:{fw_out1}")
        elif ('response status="error"' in fw_out):
            logging.error(f"{fw_ip}: Connection FAILED. API key CANNOT be obtained")
            logging.debug(f"{fw_ip}: FW API Key query response empty or invalid.")
        else:
            fw_api_key = fw_out.split("key")[1].strip("<>/ \n")
            fw_api_keys[fw_ip] = fw_api_key
            logging.debug(f"{fw_ip}: FW API Key obtained:{fw_api_key}")
            logging.info(f"{fw_ip}: Connection success. API key obtained")
            return fw_api_key
    except Exception as e:
        logging.error(f"{fw_ip}: Connection FAILED. API key CANNOT be obtained")
        return False
    return False

def get_sys_info(fw_api_key):
    curl_api = f"curl -s -k -X POST 'https://{fw_ip}/api/"
    i = 5
    while i:
        i -= 1
        try:
            cmd3 = f"{curl_api}?type=op&cmd=<show><system><info></info></system></show>&key={fw_api_key}'"
            sys_info = os.popen(cmd3).read()
            license = sys_info.split("vm-license")[1].strip("<>/ \n")
            sysip = sys_info.split("ip-address")[1].strip("<>/ \n")
            serial = sys_info.split("serial")[1].strip("<>/ \n")
            uptime = sys_info.split("uptime")[1].strip("<>/ \n")
            swver = sys_info.split("sw-version")[1].strip("<>/ \n")
            if "vm-cpu-count" in sys_info: 
                cores = sys_info.split("vm-cpu-count")[1].strip("<>/ \n") #vm-cores?
            elif "vm-cores" in sys_info:
                cores = sys_info.split("vm-cores")[1].strip("<>/ \n") #vm-cores?
            else:
                cores = 'NA'
            if "vm-memory" in sys_info:
                memory = sys_info.split("vm-memory")[1].strip("<>/ \n")
            else:
                memory = 'NA'
            break
        except Exception as e:
            logging.debug(f"{fw_ip}: System info output:{sys_info}")
            logging.debug(f"{fw_ip}: Exception getting system info:{e}. Retrying #{i}")
            continue
            #return {'license':'Error','sysip':'Error'}
        time.sleep(3)
    else:
        return {'license':'Error','sysip':'Error'}
    logging.info(f"{fw_ip}: FW system info obtained")
    return {'license':license,'sysip':sysip,'serial':serial,'uptime':uptime,'swver':swver,'cores':cores,'memory':memory}

def set_lic_api_key(fw_api_key,license_api_key):
    cmd2 = f"<request><license><api-key><set><key>{license_api_key}</key></set></api-key></license></request>"
    call2 = f"{curl_api}?type=op&cmd={cmd2}&key={fw_api_key}'"
    set_lic_api = os.popen(call2).read()
    skey = 'result' if not 'response status="error"' in set_lic_api else 'line'
    set_lic_api_result = set_lic_api.split(skey)[1].strip("<>/ \n")
    logging.info(f'{fw_ip}: API key status: {set_lic_api_result}')
    time.sleep(1)

# Connect to FWs and get details for credit estimation
for fw_ip in fw_list:

    print(f"\nProcessing {fw_list.index(fw_ip)+1}/{len(fw_list)} - {fw_ip}")

    curl_api = f"curl -s -k -X POST 'https://{fw_ip}/api/"
    # Get FW API key
    fw_api_keys[fw_ip] = connect_fw(fw_ip,username,password)
    if not fw_api_keys[fw_ip]: 
        #logging.error(f"{fw_ip}: FW connectivity failure. API key not obtained.")
        continue

    # Get FW details
    sys_info[fw_ip] = get_sys_info(fw_api_keys[fw_ip]) if fw_api_keys[fw_ip] else {'license':'Error','sysip':'Error'}

    # Print current state
    if action.lower() == 'getcores' or action.lower() == 'getstatus': continue

    # Set licensing API key
    set_lic_api_key(fw_api_keys[fw_ip],license_api_key)

    # License before upgrade
    sys_info_before_upg[fw_ip] = sys_info[fw_ip]
    logging.info(f"{fw_ip}: Current license on FW {sys_info[fw_ip].get('sysip',None)}: {sys_info[fw_ip].get('license',None)}")

    # Upgrade license
    try:
        logging.info(f"{fw_ip}: Upgrading license (in backend)...")
        cmd4 = f"<request><license><upgrade><auth-code>{dp_auth_code}</auth-code><mode>auto</mode></upgrade></license></request>"
        #call4 = f"{curl_api}?type=op&cmd={cmd4}&key={fw_api_key}'"
        #call4bg = f"{curl_api}?type=op&cmd={cmd4}&key={fw_api_key}' > /dev/null 2>&1 &"
        os.popen(f'echo {fw_ip}: >> /tmp/lic_{fw_ip}_logs 2>&1')
        call4bg = f"{curl_api}?type=op&cmd={cmd4}&key={fw_api_keys[fw_ip]}' >> /tmp/lic1_{fw_ip}_logs 2>&1 &"
        logging.debug(f"{call4bg}")
        upg_lic_api = os.popen(call4bg).read()
        time.sleep(upgsleep)
    except Exception as e:
        logging.debug(f"{fw_ip}: Exception during license upgrade:{e}, continuing to next FW")

    # License after upgrade (if waiting for license to complete, by default: skip this
    #sys_info_after_upg[fw_ip] = get_sys_info(fw_api_keys[fw_ip])

# Printing overall summary for all FW IPs
if action.lower() == 'getcores':
    fw_total = len(fw_list)
    fw_success = len(sys_info.keys())
    for f in sys_info.keys():
        coredict[f] = int(sys_info[f]['cores'].strip())
    res = Counter(coredict.values())
    summary = []
    total = 0
    totalfws = 0
    headers = ['Category','Firewalls']
    for r in sorted(res.keys()):
        summary += [[f"{r} cores",res[r]]]
        total += r*res[r]
        totalfws += res[r]
    #summary += [["--------","---"],["Total",len(res.keys())],["--------","---"]]
    summary += [["--------","---"],["Total",totalfws],["--------","---"]]
    print("\n---------------\nCORES SUMMARY:\n---------------\n")
    print(tabulate(summary,headers=headers))
    print("\nDone!")
    exit()

if action.lower() == 'getstatus':
    fw_total = len(fw_list)
    fw_success = len(sys_info.keys())
    for f in sys_info.keys():
        coredict[f] = int(sys_info[f]['cores'].strip())
    res = Counter(coredict.values())
    print("\n-----------------\nCURRENT SUMMARY:\n-----------------\n")
    summary = []
    headers = ['Firewall IP','Serial Number','SW Version','Cores','Current License']
    for fw_ip in fw_list:
        try:
            summary += [[fw_ip,sys_info[fw_ip].get('serial',None),sys_info[fw_ip].get('swver',None),\
                         sys_info[fw_ip].get('cores',None),sys_info[fw_ip].get('license',None)]]
        except Exception as e:
            logging.debug(f"{fw_ip}: Exception during fetching current license:{e}")
            summary += [[fw_ip,'Failed to connect','na','na','na','na','na','na']]
    print(tabulate(summary,headers=headers))
    print("\nDone!")
    exit()

if action.lower() == 'upgrade':
        # Wait time before verifications
    print("\n\n")
    logging.info(f"License upgrade attempt is completed for all {len(fw_list)} FWs.\n\n")
    print("\n")
    logging.info(f"Waiting for {waittime/60} mins, before checking each firewall license status")
    time.sleep(waittime)
        
    # Checking license info on each FW    
    for fw_ip in fw_list:
        curl_api = f"curl -s -k -X POST 'https://{fw_ip}/api/"
        print(f"\n{fw_ip}")
        if not fw_api_keys.get(fw_ip,False):
            logging.error(f"{fw_ip}: License upgrade NOT attempted on {fw_ip} as the API key is not obtained")
            continue
        
        fw_api_key = fw_api_keys[fw_ip]
        logging.debug(f"{fw_ip}: API key:{fw_api_key}")
        
        # License after upgrade (if waiting for license to complete, by default: skip this
        sys_info_after_upg[fw_ip] = get_sys_info(fw_api_keys[fw_ip])
        logging.info(f"{fw_ip}: Current license on FW {sys_info_after_upg[fw_ip].get('sysip',None)}: {sys_info_after_upg[fw_ip].get('license',None)}")
        
        # Result
        old_lic = sys_info_before_upg[fw_ip].get('license',None)
        new_lic = sys_info_after_upg[fw_ip].get('license',None)
        logging.info(f"{fw_ip}: Old license: {old_lic}. New license: {new_lic}")
        if ('flex' in new_lic.lower()) or ('series' in new_lic.lower()):
            logging.info(f"{fw_ip}: License upgrade to FLEX SUCESSFUL")
        else:
            logging.error(f"{fw_ip}: License upgrade to FLEX FAILED")

    print("\n-------------------\nUPGRADE SUMMARY:\n-------------------\n")
    summary = []
    headers = ['Firewall IP','Serial Number','SW Version','Cores','Previous License','Current License']
    for fw_ip in fw_list:
        try:
            summary += [[fw_ip,sys_info_before_upg[fw_ip].get('serial',None),sys_info_before_upg[fw_ip].get('swver',None),\
                         sys_info_before_upg[fw_ip].get('cores',None),sys_info_before_upg[fw_ip].get('license',None),\
                         sys_info_after_upg[fw_ip].get('license',None)]]
        except Exception as e:
            summary += [[fw_ip,'Failed to connect','na','na','na','na','na','na']]
    print(tabulate(summary,headers=headers))
    print("\nDone!")


