# bulk-license-upgrade
Upgrade licenses from Perpetual/Enterprise to a Flexible credit based deployment profile

Tool features/objectives:
-------------------------
1. Get the current number of firewalls against each core value from the list of FWs provided (to help with assessing the credit requirements).
2. Get the current status of license on each firewall. To identify FWs requiring migration. (Also to re-check the license state of FWs post license upgrade operation).
3. Migrate the FWs from enterprise/perpetual license to a flexible deployment profile authcode provided by user.

Pre-requisites:
---------------
1. Server with latest python installed.
2. Python modules required: random, concurrent, requests, collections, tabulate, json, argparse, logging, time, os
3. All the Firewalls (to be upgraded) must be reachable from the server in #1.
4. All the Firewalls (to be upgraded) to be connected to a Panorama.
5. All the Firewalls (to be upgraded) should be online and should be able to reach to CSP.
6. All the Firewalls (to be upgraded) should have valid (not expired) existing license.
7. Minimum PanOS version required in each release: 10.0.10+, 10.1.12+, 10.2.8+, 11.0.4+. (Flexible deployment profile is not supported for 10.0.4 and below panos versions)

Procedure workflow:
-------------------
1. From the panorama, going to respective DG, configure a temporary username and password with administrator access. Push this config down to all applicable FWs.
2. From the CSP, obtain the 'Licensing API key' and the 'Deployment Profile' to which the FWs need to be migrated. Path: Products -> API Key Management -> Licensing API.
3. Provide the username, password, license api key and deployment profile values to an input json file (refer to sample_input.json).
4. Provide the list of firewall IPs (which need to be migrated to flex license) in a text file (refer to sample_iplist.txt).
5. Trigger the script as below.
6. After script completion, from panorama, remove the user credentials created in step 1, for security.

Script Arguments:
-----------------
python license_upgrade.py <arguments as below>
	Mandatory args:
	-input <input.json>	The input json file with all required info, refer sample_input.json
	-iplist <iplist.txt>	The input IP list file with one IP per row, refer sample_iplist.txt
	-action	<getcores|getstatus|upgrade>	
            Provide 'getcores' - to get the number of FWs against each core value
			Provide 'getstatus' - to get the current license state of each FW
			Provide 'upgrade' - to trigger upgrade for all FWs
	Optional args:
	-log debug		To get the debug logs printed incase of failures. (default: info)

Sample command to trigger the script:
-------------------------------------
python license_upgrade.py -action <getcores|getstatus|upgrade> -input <input-json-file> -iplist <input-ip-list-file> -log <info|debug>
