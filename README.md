# bulk-license-upgrade
Upgrade licenses from Perpetual/Enterprise to a Flexible credit based deployment profile

Pre-requisites:
---------------
1. Server with latest python installed.
2. Python modules required: collections, tabulate, json, argparse, logging, time, os
3. All the Firewalls (to be upgraded) must be reachable from the server in #1.
4. All the Firewalls (to be upgraded) to be connected to a Panorama.
5. All the Firewalls (to be upgraded) should be online and should be able to reach to CSP.
6. All the Firewalls (to be upgraded) should have valid (not expired) existing license.

Procedure workflow:
-------------------
1. From the panorama, going to respective DG, configure a temporary username and password with administrator access. Push this config down to all applicable FWs.
2. From the CSP, obtain the 'Licensing API key' and the 'Deployment Profile' to which the FWs need to be migrated.
3. Provide the username, password, license api key and deployment profile values to an input json file (refer to sample_input.json).
4. Provide the list of firewall IPs (which need to be migrated to flex license) in a text file (refer to sample_iplist.txt).
5. Trigger the script as below.

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
