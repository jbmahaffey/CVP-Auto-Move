#!/usr/bin/env python3

import sys
import os
import yaml
from cvprac.cvp_client import CvpClient
import argparse
import ssl
import logging
ssl._create_default_https_context = ssl._create_unverified_context

def Main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cvp', default='', help='CVP Server IP')
    parser.add_argument('--username', default='', help='CVP username')
    parser.add_argument('--password', default='', help='CVP password')
    parser.add_argument('--logging', default='', help='Logging levels info, error, or debug')
    parser.add_argument('--devlist', default='devices.yml', help='YAML file with list of approved devices.')
    args = parser.parse_args()

    # Only enable logging when necessary
    if args.logging != '':
        logginglevel = args.logging
        formattedlevel = logginglevel.upper()

        # Open logfile
        logging.basicConfig(format='%(asctime)s %(levelname)-8s %(message)s',filename='cvpmove.log', level=formattedlevel, datefmt='%Y-%m-%d %H:%M:%S')
    else:
        ()

    # Open YAML variable file
    with open(os.path.join(sys.path[0],args.devlist), 'r') as vars_:
        data = yaml.safe_load(vars_)

    # CVPRAC connect to CVP
    clnt = CvpClient()
    try:
        clnt.connect(nodes=[args.cvp], username=args.username, password=args.password)
    except:
        logging.error('Unable to login to Cloudvision')

    # Get devices from Undefined container in CVP and add their MAC to a list
    undefined = clnt.api.get_devices_in_container('Undefined')
    undef = []
    for unprov in undefined:
        undef.append(unprov['systemMacAddress'])

    # Compare list of devices in CVP undefined container to list of approved devices defined in YAML file
    # If the the device is defined in the YAML file then provision it to the proper container
    for dev in data['all']:
        if dev['mac'] in undef:
            device = clnt.api.get_device_by_mac(dev['mac'])
            try:
                clnt.api.deploy_device(device=device, container=dev['container'], )
            except:
                logging.error('Unable to deploy device.')
        else:
            logging.info('device ' + str(undef) + ' not approved for deployment or already provisioned.')
    
    # Run the task using the Execute function
    task = Execute(clnt, data)

# Function to run task if they are for the devices we provisioned
def Execute(clnt, data):
    t = clnt.api.get_tasks()
    approved = []
    for device in data['all']:
        approved.append(device['mac'])    
    
    for task in t['data']:
        if task['data']['NETELEMENT_ID'] in approved and task['workOrderUserDefinedStatus'] == 'Pending':
            clnt.api.execute_task(task['workOrderId'])
        else:
            logging.info('Task ID ' + str(task['workOrderId']) + ' is ' + str(task['workOrderUserDefinedStatus']) + '.')
    

if __name__ == '__main__':
   Main()