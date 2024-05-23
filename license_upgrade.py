# READ ME
# Built in modules being used: os, time, logging, argparse, json, collections, concurrent, random
# New modules required: tabulate (inorder to show summary), requests

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
import requests
import concurrent.futures
import random

# Argument Parsing
parser = argparse.ArgumentParser()
parser.add_argument( '-input',required=True,help='Provide input filename which has credential details, refer sample.json')
parser.add_argument( '-iplist',required=True,help='Provide input file with all Firewall IPs (One IP per line)')
parser.add_argument( '-action',required=True,help='Provide,\
                                                   \ngetcores - to get the count of Firewalls with x cores.\
                                                   \ngetstatus - to get the current license on each Firewall.\
                                                   \nupgrade - to trigger upgrade for each Firewall.')
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

requrls = []
reqfws  = []

# Reading user input of FW IPs to be upgraded
iname=args.iplist
fw_list = open(iname,'r').readlines()
fw_list = [f.strip("\n\r ") for f in fw_list] 
logging.info(f"List of Firewalls to be upgraded:\n{fw_list}")

action = args.action

sys_info = {}
sys_info_before_upg = {}
sys_info_after_upg = {}
fw_api_keys = {}
new_lics = {}
old_lics = {}
coredict = {}
requests.packages.urllib3.disable_warnings(category=requests.packages.urllib3.exceptions.InsecureRequestWarning)
logging.getLogger("requests.packages.urllib3").setLevel(logging.CRITICAL)
logging.getLogger("urllib3").propagate = False

def query_api(action, url, headers={}, payload={}, options={}, verify=False, timeout=30, maxretry=1, upgradecall=False):

    if upgradecall:
        logging.debug(f"Sleeping randomly for a max of 10 secs to avoid too many requests sent at once")
        time.sleep(random.randint(1,60))

    # maxretry fixed to 1 for now
    for i in range(maxretry):
        i+=1
        try:
            if action == 'post':
                response = requests.post(url, headers=headers, verify=verify, timeout=timeout, json=payload, params=options)
            else:
                response = requests.get(url, headers=headers, verify=verify, timeout=timeout, json=payload, params=options)

            if response and response.text:
                logging.info(f"Response is received")
                logging.debug(f"Response obtained: {response}")
                return response.text
            else:
                logging.error(f"Error with query response: {response}.")
                return 'ResponseError'
        except Exception as e:
            logging.error(f"Error with connection.")
            logging.debug(f"Error:{e}")
            return 'ConnectError'

def connect_fw(fw_ip,username,password):
    # Get FW API key
    try:
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'connect-timeout': 10, 'max-time': 150, 'retry': 5, 'retry-delay': 5, 'retry-max-time': 100}
        requrl  = f"https://{fw_ip}/api/?type=keygen"
        creds = {'user': username, 'password': password}
        fw_out = query_api('get', requrl, headers, payload, options=creds)

        #logging.debug(f"{fw_ip}: FW API key query output:{fw_out}**")
        if not fw_out:
            logging.error(f"{fw_ip}: Connection FAILED. API key CANNOT be obtained")
            logging.debug(f"{fw_ip}: Firewall connectivity failed. Error:{fw_out}")
        elif ('response status="error"' in fw_out) or fw_out in ('ResponseError','ConnectError'):
            logging.error(f"{fw_ip}: Connection FAILED. API key CANNOT be obtained")
            logging.debug(f"{fw_ip}: Firewall API Key query response empty or invalid.")
        else:
            fw_api_key = fw_out.split("key")[1].strip("<>/ \n")
            fw_api_keys[fw_ip] = fw_api_key
            #logging.debug(f"{fw_ip}: FW API Key obtained:{fw_api_key}")
            logging.info(f"{fw_ip}: Connection success. API key obtained")
            return fw_api_key
    except Exception as e:
        logging.error(f"{fw_ip}: Connection FAILED. API key CANNOT be obtained")
        return False
    return False

def get_sys_info(fw_api_key):
    i = 5
    while i:
        i -= 1
        try:
            requrl  = f"https://{fw_ip}/api/?type=op&cmd=<show><system><info></info></system></show>&key={fw_api_key}"
            sys_info = query_api('post', requrl, maxretry=1)

            if sys_info in ('ResponseError','ConnectError'):
                logging.debug(f"Connection error: {sys_info}. Retrying #{i}")
                continue

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
        time.sleep(5)
    else:
        return {'license':'Error','sysip':'Error'}
    logging.info(f"{fw_ip}: Firewall system info obtained")
    return {'license':license,'sysip':sysip,'serial':serial,'uptime':uptime,'swver':swver,'cores':cores,'memory':memory}

def set_lic_api_key(fw_api_key,license_api_key):
    cmd2 = f"<request><license><api-key><set><key>{license_api_key}</key></set></api-key></license></request>"

    requrl  = f"https://{fw_ip}/api/?type=op&cmd={cmd2}&key={fw_api_key}"
    set_lic_api = query_api('post', requrl)

    if set_lic_api in ('ResponseError','ConnectError'):
        logging.error(f"Connection error: {sys_info}. Retrying #{i}")
        return 'Error'

    skey = 'result' if not 'response status="error"' in set_lic_api else 'line'
    set_lic_api_result = set_lic_api.split(skey)[1].strip("<>/ \n")
    logging.info(f'{fw_ip}: Setting API key status: {set_lic_api_result}')
    time.sleep(5)

# Connect to FWs and get details for credit estimation
future = {}
for fw_ip in fw_list:

    action_set = ('getcores', 'getstatus', 'upgrade')
    if action not in action_set:
        logging.error(f"Invalid action specified: {action}. Must be one of: {action_set}")
        exit()

    print(f"\n\nProcessing Firewall {fw_list.index(fw_ip)+1}/{len(fw_list)} - IP: {fw_ip}")

    logging.info(f"{fw_ip}: Connecting to Firewall")

    # Get FW API key
    fw_api_keys[fw_ip] = connect_fw(fw_ip,username,password)
    if not fw_api_keys[fw_ip]: 
        logging.error(f"{fw_ip}: Firewall is skipped due to connectivity failure and no API key obtained.")
        continue

    # Get FW details
    logging.info(f"{fw_ip}: Getting Firewall license info")
    sys_info[fw_ip] = get_sys_info(fw_api_keys[fw_ip]) if fw_api_keys[fw_ip] else {'license':'Error','sysip':'Error'}

    # Print current state
    if action.lower() == 'getcores' or action.lower() == 'getstatus': continue

    # Set licensing API key
    logging.info(f"{fw_ip}: Setting Firewall license api key")
    set_lic_api_key(fw_api_keys[fw_ip],license_api_key)

    # License before upgrade
    sys_info_before_upg[fw_ip] = sys_info[fw_ip]
    logging.info(f"{fw_ip}: Current license on Firewall {sys_info[fw_ip].get('sysip',None)}: {sys_info[fw_ip].get('license',None)}")

    # Upgrade command list
    logging.info(f"{fw_ip}: License upgrade will be attempted for this firewall")
    cmd4 = f"<request><license><upgrade><auth-code>{dp_auth_code}</auth-code><mode>auto</mode></upgrade></license></request>"
#    cmd4 = f"<request><license><deactivate><VM-Capacity><mode>auto</mode></VM-Capacity></deactivate></license></request>"
#    cmd4 = f"<request><license><fetch><auth-code>A2780910</auth-code></fetch></license></request>"
    requrl  = f"https://{fw_ip}/api/?type=op&cmd={cmd4}&key={fw_api_keys[fw_ip]}"
    requrls += [requrl]
    reqfws += [fw_ip]

# Printing overall summary for all FW IPs
if action.lower() == 'getcores':
    fw_total = len(fw_list)
    fw_success = len(sys_info.keys())
    fw_failed = list(set(fw_list)-set(sys_info.keys()))
    for f in sys_info.keys():
        coredict[f] = int(sys_info[f]['cores'].strip())
    res = Counter(coredict.values())
    summary = [["unknown cores",len(fw_failed)]] if len(fw_failed) else []
    total = 0
    totalfws = len(fw_failed)
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

if action.lower() == 'upgrade':
    print(f"\n\n")
    logging.info(f"Attempting license upgrade (in parallel) on these {len(requrls)} (out of total {len(fw_list)}) Firewalls: {reqfws}")
    logging.debug(f"Attempt URLs: {requrls}")
    
    with concurrent.futures.ThreadPoolExecutor() as exe:
        future_to_url = {exe.submit(query_api, 'post', url, timeout=300, upgradecall=True): url for url in requrls}
        logging.info(f"Waiting {waittime} for response")
        time.sleep(waittime)
        logging.debug(f"Sleep time is over")
    
        for future in concurrent.futures.as_completed(future_to_url):
            url = future_to_url[future]
            try:
                logging.debug(f"Attempted \nfuture:{future}, \nurl:{url}")
                data = future.result()
            except Exception as exc:
                logging.error('%r generated an exception: %s' % (url, exc))
            else:
                logging.info(f'Firewall: {url.split("/")[2]}. Upgrade response: {data}')
    
    print("\n\n")
    logging.info(f"License upgrade attempt is completed for all {len(requrls)} Firewalls.")

    # Wait time before verifications
    time.sleep(90)
        
    # Checking license info on each FW    
    for fw_ip in fw_list:
        print(f"\nFirewall: {fw_ip}")
        if not fw_api_keys.get(fw_ip,False):
            logging.error(f"{fw_ip}: License upgrade NOT attempted on {fw_ip} as the API key is not obtained")
            continue
        
        fw_api_key = fw_api_keys[fw_ip]
        logging.debug(f"{fw_ip}: API key:{fw_api_key}")
        
        # License after upgrade (if waiting for license to complete, by default: skip this
        sys_info_after_upg[fw_ip] = get_sys_info(fw_api_keys[fw_ip])
        logging.info(f"{fw_ip}: Current license on Firewall {sys_info_after_upg[fw_ip].get('sysip',None)}: {sys_info_after_upg[fw_ip].get('license',None)}")
        
        # Result
        old_lic = sys_info_before_upg[fw_ip].get('license',None)
        new_lic = sys_info_after_upg[fw_ip].get('license',None)
        logging.info(f"{fw_ip}: Old license: {old_lic}. New license: {new_lic}")
        if ('flex' in new_lic.lower()) or ('series' in new_lic.lower()):
            logging.info(f"{fw_ip}: SUCCESS: License on the firewall is a Flexible Model license")
        else:
            logging.error(f"{fw_ip}: FAILED: License on the firewall is a NOT a Flexible Model license")

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


