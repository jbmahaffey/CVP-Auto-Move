#!/usr/bin/env python3

import sys
import csv
import os
import requests
import yaml
from cvprac.cvp_client import CvpClient
import argparse
import ssl
import logging
ssl._create_default_https_context = ssl._create_unverified_context

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cvp', default='192.168.101.26', help='CVP Server IP')
    parser.add_argument('--username', default='cvpadmin', help='CVP username')
    parser.add_argument('--password', default='', help='Cloudvision password')
    parser.add_argument('--logging', default='', help='Logging levels info, error, or debug')
    parser.add_argument('--devlist', default='devices.csv', help='YAML/CSV file with list of approved devices.')
    args = parser.parse_args()

    # Only enable logging when necessary
    if args.logging != '':
        logginglevel = args.logging
        formattedlevel = logginglevel.upper()

        # Open logfile
        logging.basicConfig(
            format='%(asctime)s %(levelname)-8s %(message)s',
            filename='cvpmove.log', 
            level=formattedlevel, 
            datefmt='%Y-%m-%d %H:%M:%S',
        )
    else:
        ()
        
    # Open variable file either csv or yaml
    filetype = args.devlist.split('.')
    if filetype[1] == 'yml':
        # Open YAML variable file
        with open(os.path.join(sys.path[0],args.devlist), 'r') as vars_:
            data = yaml.safe_load(vars_)
    elif filetype[1] == 'csv':
        devices = []
        with open(os.path.join(sys.path[0],args.devlist), 'r') as vars_:
            for line in csv.DictReader(vars_):
                devices.append(line)
        data = {'all': devices}
    else:
        logging.info('Please enter a valid file type.')

    # CVPRAC connect to CVP
    client = CvpClient()
    try:
        client.connect(
            nodes=[args.cvp], username=args.username, password=args.password,
        )
    except:
        logging.error('Unable to login to Cloudvision')

    # Get devices from Undefined container in CVP and add their MAC to a list
    try:
        undefined = client.api.get_devices_in_container('Undefined')
    except:
        logging.error('Unable to get devices from Cloudvision.')

    undef = []
    for unprov in undefined:
        undef.append(unprov['systemMacAddress'])

    # Compare list of devices in CVP undefined container to list of approved
    # devices defined in YAML file If the the device is defined in the YAML file
    # then provision it to the proper container
    for dev in data['all']:
        if dev['mac'] in undef:
            device = client.api.get_device_by_mac(dev['mac'])
            try:
                tsk = client.api.deploy_device(
                    device=device, container=dev['container'],
                )
                execute(client, tsk['data']['taskIds'])
                con = configlet(
                    client, dev, args.cvp, args.username, args.password,
                )
                if con != None and con != 'reconcile':
                    assign = assign_configlet(client, dev, con)
                    execute(client, assign['data']['taskIds'])
                elif con == 'reconcile':
                    cfglets = container_cfg(client, dev)
                    execute(client, cfglets['data']['taskIds'])
                else:
                    ()
            except:
                logging.error('Unable to deploy device.')
        else:
            logging.info(
                f'device {undef} not approved for deployment or already'
                ' provisioned.'
            )


configlet_template = '''\
hostname {hostname}
interface management1
ip address {ip}/24
no shut
ip route 0.0.0.0/0 {mgmtgateway}
daemon TerminAttr
exec /usr/bin/TerminAttr -ingestgrpcurl=192.168.101.26:9910\
  -cvcompression=gzip -ingestauth=key,arista\
  -smashexcludes=ale,flexCounter,hardware,kni,pulse,strata\
  -ingestexclude=/Sysdb/cell/1/agent,/Sysdb/cell/2/agent\
  -ingestvrf=default -taillogs
no shut\
'''

def configlet(client, data, cvp, user, password):
    '''Function to create configlet for management

    '''
    l = []
    try:
        config = client.api.get_configlets(start=0, end=0)
        ztp = client.api.get_device_by_mac(data['mac'])
    except:
        logging.error('Unable to get list of configlets.')

    for configlet in config['data']:
        l.append(configlet['name'])
    
    if data['hostname'] + str('_mgmt') in l:
        logging.info(f'configlet {data["hostname"]} mgmt already exist')
    elif ztp['ztpMode'] == 'true':
        try:
            cfglt = client.api.add_configlet(
                name=f"{data['hostname']}_mgmt", 
                config=configlet_template.format(**data),
            )
            return cfglt
        except:
            logging.error(
                f'Unable to create configlet {data["hostname"]}_mgmt'
            )
    else:
        try:
            container = client.api.get_container_by_name(name=data['container'])
            ckey = container['key']

            login = (
                f'https://{cvp}/cvpservice/login/authenticate.do'
            )
            resp = requests.post(
                login, 
                headers={'content-type': 'application/json'},
                json={'userId': user, 'password': password}, 
                verify=False,
            )

            jresp = resp.json()
            token = jresp['cookie']['Value']

            url = (
                f'https://{cvp}/cvpservice/provisioning/'
                'containerLevelReconcile.do'
                f'?containerId={ckey}&reconcileAll=false'
            )
            response = requests.get(
                url, 
                auth=(user, password), 
                headers={'Cookie': f'access_token={token}'}, 
                verify=False,
            )
            if response.status_code == 200:
                reconcile = 'reconcile'
            return reconcile
        except:
            logging.error('Unable to reconcile container.')


def assign_configlet(client, dev, con):
    '''Function to assign configlet to new device

    '''
    try:
        device = client.api.get_device_by_mac(dev['mac'])
    except:
        logging.error('Unable to get device information from Cloudvision')

    cfglets = [{'name': f"{dev['hostname']} mgmt", 'key': con}]
    try:
        task = client.api.apply_configlets_to_device(
            app_name='mgmt_configlet', dev=device, new_configlets=cfglets,
        )
        return task
    except:
        logging.error('Error applying configlet to device.')


def container_cfg(client, data):
    cfglets = client.api.get_configlets_by_device_id(data['mac'])

    cfg_list = []
    for configlet in cfglets:
        cfg_list.append({'name': configlet['name'], 'key': configlet['key']})

    device = client.api.get_device_by_mac(data['mac'])
    task = client.api.apply_configlets_to_device(
        app_name='container_configlet', dev=device, new_configlets=cfg_list,
    )
    return task


def execute(client, tasks):
    '''Function to run task if they are for the devices we provisioned

    '''
    for task in tasks:
        try:
            client.api.execute_task(task_id=task)
        except:
            logging.info(
                f'Task ID {task} is failed to execute.'
            )
    

if __name__ == '__main__':
   main()