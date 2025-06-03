#!/usr/bin/env python3

import csv
import json
import requests
import argparse
import getpass
import urllib3
import logging
import time
import os
from pathlib import Path

# Constants
LOG_DIR = Path("logs")
OUTPUT_DIR = Path("outputs")

# Prepare environment
LOG_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    filename='logs/f5_as3.log',
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set default variable values
auth_token = None
auth_token_expiry = 0

def global_token_auth(host, username, password):
    global auth_token
    global auth_token_expiry
    # Check if current epoch time is less than token expiry;
    # skip token generation if not
    if time.time() < auth_token_expiry:
        logger.debug(f"Token still valid. Expires in {auth_token_expiry - time.time()} seconds.")
        return
    # request a new token
    url = f'https://{host}/mgmt/shared/authn/login'
    payload = {'username': username, 'password': password, 'provider': 'tmos'}
    headers = {'Content-type': 'application/json'}
    logger.debug(f'Token API call: {url}, {headers}, {username}')
    try:
        response = requests.post(url, json=payload, headers=headers, verify=False)
        response.raise_for_status()
        data = response.json()['token']
        auth_token = data['token']
        auth_token_expiry = data['exp']
        logger.debug(f"New token retrieved. Expires at {auth_token_expiry} (epoch)")
    except Exception as e:
        logger.error(f"Failed to retrieve auth token: {e}")
        exit_script()
    return

def bigiq_http_get(host, username, password, uri, params):
    global_token_auth(host, username, password)
    try:
        url = f'https://{host}/{uri}'
        headers = {
            'Content-type': 'application/json',
            'X-F5-Auth-Token': auth_token
            }
        logger.debug(f'BIG-IQ HTTP GET {url} {params}')
        response = requests.get(url,headers=headers,params=params,verify=False)
        response.raise_for_status()  # Raise an exception for bad status codes
        logger.debug(f'BIG-IP API Response: {response.text}')
        return response
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e}')
        exit_script()

def parse_command_line_arguments():
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Collect AS3 configurations from a BIG-IQ and output them to a CSV or JSON file"
    )
    parser.add_argument("--username", help="Username for BIG-IQ")
    parser.add_argument("--password", help="Password for BIG-IQ user")
    parser.add_argument("--hostname", help="BIG-IQ host (IP/FQDN)")
    
    # Read command line arguments
    args = parser.parse_args()
    
    args.hostname = args.hostname or input("Enter BIG-IQ hostname: ")
    args.username = args.username or input("Enter BIG-IQ username: ")
    args.password = args.password or getpass.getpass("Enter BIG-IQ password: ")

    return args.hostname, args.username, args.password

def exit_script(msg=None):
    if msg is not None:
        logger.warning(f'{msg}')
    logger.debug('Exiting script due to exit_script function call.')
    SystemExit()

def write_output_csv(filename, data):
    path = OUTPUT_DIR / filename
    with open(path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
    logger.info(f"CSV written to {path}")

def write_output_json(filename, data):
    path = OUTPUT_DIR / filename
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    logger.info(f"JSON written to {path}")
        
if __name__ == '__main__':
    ##
    ## Main application code is in this function
    ##
    
    # Start logging
    logger.info('F5 BIG-IQ AS3 Export (includes RBAC) started')
    
    # Parse command line arguments
    logger.debug('Parsing command line arguments') 
    try:
        host, username, password = parse_command_line_arguments()
    except Exception as e:
        logger.error('Error parsing command line arguments: {}'.format(e))
        exit_script()

    # Retrieve the Application list from the BIG-IQ
    logger.debug('Retrieving Application List from BIG-IQ')
    try:
        as3_config = bigiq_http_get(host, username, password, 'mgmt/ap/query/v1/tenants/default/reports/ApplicationsList', {'view': 'all', "$top": 500})
        logger.debug(f'Application List Text: {as3_config.text}')
        if as3_config is None:
            logger.error('No response returned from BIG-IQ')
            exit_script()
        else:
            as3_config_json = as3_config.json()
            logger.debug(f'Application List JSON: {as3_config_json}')
    except Exception as e:
        logger.error(f'Error retrieving AS3 configuration from BIG-IQ at {host}: {e}')
        exit_script()

    # Retrieve the application count from BIG-IQ
    try:
        applicationCount = as3_config_json['result']['totalItems']
        logger.info(f'Retrieved {applicationCount} applications from BIG-IQ at {host}')
    except Exception as e:
        logger.error(f'Error parsing Application count from BIG-IQ at {host}: {e}')
        exit_script()
    
    # Retrieve all AS3 declarations from BIG-IQ
    as3_inventory = bigiq_http_get(host, username, password, '/mgmt/shared/appsvcs/declare', {})
    as3_inventory = as3_inventory.json()

    # Parse the list of applications returned
    try:
        applicationList = []
        for currentApplication in as3_config_json['result']['items']:
            currentApplicationExport = {}
            currentApplicationExport['name'] = currentApplication['name']
            currentApplicationExport['id'] = currentApplication['id']
            currentApplicationExport['selfLink'] = currentApplication['selfLink']
            currentApplicationExport['serviceCount'] = currentApplication['serviceCount']
            applicationList.append(currentApplicationExport)
    except Exception as e:
        logger.error(f'Error parsing Application list from BIG-IQ at {host}: {e}')
        exit_script()

    # Retrieve each application service from BIG-IQ
    logger.info('Retrieving Application Services from BIG-IQ')
    applicationServiceList = []
    for currentApplication in applicationList:
        try:
            applicationServicesResponse = bigiq_http_get(host, username, password, 'mgmt/ap/query/v1/tenants/default/reports/ApplicationServicesList', {'$appId': currentApplication['id']})
            currentApplicationServiceList = applicationServicesResponse.json()['result']['items']
            for currentApplicationService in currentApplicationServiceList:
                logger.debug(f'Processing Application Service: {currentApplicationService}')
                currentApplicationServiceExport = {}
                currentApplicationServiceExport['parentApplication'] = currentApplication['name']
                currentApplicationServiceExport['parentApplicationId'] = currentApplication['id']
                currentApplicationServiceExport['parentApplicationSelfLink'] = currentApplication['selfLink']
                currentApplicationServiceExport['name'] = currentApplicationService['name']
                currentApplicationServiceExport['id'] = currentApplicationService['id']
                currentApplicationServiceExport['globalAppId'] = currentApplicationService['globalAppId']
                currentApplicationServiceExport['status'] = currentApplicationService['status']
                currentApplicationServiceExport['health'] = currentApplicationService['health']
                currentApplicationServiceExport['activeAlerts'] = currentApplicationService['activeAlerts']              
                currentApplicationServiceExport['enhancedAnalytics'] = currentApplicationService['enhancedAnalytics']
                currentApplicationServiceExport['deploymentType'] = currentApplicationService['deploymentType']
                if currentApplicationService['deploymentType'] == 'AS3':
                    # Search the list of dictionaries of AS3 declarations for the current application service
                    tenantName = currentApplicationService['name'].split('_')[0]
                    applicationName = currentApplicationService['name'].split('_', 1)[1:][0]
                    for currentDeclaration in as3_inventory:
                        if tenantName in currentDeclaration.keys():
                            if applicationName in currentDeclaration[tenantName].keys():
                                currentApplicationServiceExport['AS3Declaration'] = currentDeclaration
                                currentApplicationServiceExport['target'] = currentDeclaration['target']['address']
                                currentApplicationServiceExport['tenantName'] = currentApplicationService['name'].split('_')[0]
                                currentApplicationServiceExport['applicationName'] = currentApplicationService['name'].split('_', 1)[1:][0]
                                logger.debug(f'Application service {currentApplicationService["name"]} is AS3; adding AS3 declaration')
                else:
                    logger.debug(f'Application service {currentApplicationService["name"]} is not AS3; skipping')
                applicationServiceList.append(currentApplicationServiceExport)
                logger.debug(f'Recognized Application Service: {currentApplicationServiceExport}')
        except Exception as e:
            logger.error(f'Error retrieving Application Services from BIG-IQ at {host}: {e}')
            exit_script()


    # Output the list of applications to a CSV    
    logger.info('Outputting Application List to CSV')
    with open('outputs/app_services_inventory.csv', 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=['parentApplication', 'parentApplicationId', 'parentApplicationSelfLink', 'name', 'id', 'globalAppId', 'status', 'health', 'activeAlerts', 'enhancedAnalytics', 'deploymentType', 'tenantName', 'applicationName'])
        writer.writeheader()
        for row in applicationServiceList:
            writer.writerow({key: row.get(key, '') for key in writer.fieldnames})
        logger.debug(f'Output to file: Application List CSV: {applicationServiceList}')
    
    # Output the list of applications to a JSON
    logger.info('Outputting Application List to JSON')
    with open('outputs/app_services_inventory.json', 'w') as jsonfile:
        json.dump(applicationServiceList, jsonfile, indent=2)
        logger.debug(f'Output to file: Application List JSON: {applicationServiceList}')

    # Export RBAC sections
    rbac_endpoints = {
        'rbac_roles.json': 'mgmt/shared/authorization/roles',
        'rbac_role_types.json': 'mgmt/shared/authorization/role-types',
        'rbac_resource_groups.json': 'mgmt/shared/authorization/resource-groups',
        'rbac_users.json': '/mgmt/shared/authz/users',
        'rbac_user_groups.json': 'mgmt/shared/authn/providers/local/groups'
    }   
    
    for filename, endpoint in rbac_endpoints.items():
        response = bigiq_http_get(host, username, password, endpoint, {})
        write_output_json(filename, response.json())
            
    logger.info("RBAC export completed.")
    
    exit_script()