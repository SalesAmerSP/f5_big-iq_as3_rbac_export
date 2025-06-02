import csv
import json
import requests
import argparse
import getpass
import urllib3
import logging
import time
import os

# Verify that the logging folder exists and create it if not
if not os.path.exists('logs'):
    os.makedirs('logs')

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    filename='logs/f5_as3.log',
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Log an instantiation message
logger.info('F5 BIG-IQ AS3 Export (includes RBAC) launched')

# Configure console logging
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console)

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def global_token_auth():
    global auth_token
    global auth_token_expiry
    try:
        auth_token
        auth_token_expiry
    except NameError:
        logger.debug('The variables auth_token or auth_token_expiry not found; creating variables with dummy values')
        auth_token = 'null'
        auth_token_expiry = 0
    # Check if current epoch time is less than token expiry;
    # skip token generation if not
    if (time.time() < auth_token_expiry):
        remaining_seconds = auth_token_expiry - time.time()
        logger.debug(f'Existing authentication token is still valid. Expires in {remaining_seconds} seconds.')
        return
    # request a new token
    url = f'https://{host}/mgmt/shared/authn/login'
    payload = {'username': username, 'password': password, 'provider': 'tmos'}
    headers = {'Content-type': 'application/json'}
    logger.debug(f'Token API call: {url}, {headers}, {username}')
    try:
        response = requests.post(
            url,
            json=payload,
            headers=headers
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e}')
        SystemExit()
    try:
        auth_token = response.json()['token']['token']
        auth_token_expiry = response.json()['token']['exp']
        logger.debug(f'Auth token retrieved with expiration of {auth_token_expiry} epoch time')
    except KeyError as e:
        logger.error(f'Error retrieving auth token: JSON key not found in response: {response.text} - {e}')
        SystemExit()
    return

def bigiq_http_get(uri, params):
    global_token_auth()
    url = f'https://{host}/{uri}'
    headers = {
        'Content-type': 'application/json',
        'X-F5-Auth-Token': auth_token
        }
    logger.debug(f'BIG-IQ HTTP GET URL:{url} {params}')
    try:
        response = requests.get(
            url,
            headers=headers,
            params=params
        )
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logger.error(f'Error making API call: {e}')
        SystemExit()
    logger.debug(f'BIG-IP API Response: {response.text}')
    return response

def parse_command_line_arguments():
    # Define BIG-IQ environment variables
    global username
    global password
    global host
    global csv_filename
    global json_filename
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Collect AS3 configurations from a BIG-IQ and output them to a CSV or JSON file"
    )
    parser.add_argument("--username", type=str, help="Username for BIG-IQ")
    parser.add_argument("--password", type=str, help="Password for BIG-IQ user")
    parser.add_argument("--hostname", type=str, help="BIG-IQ host (IP/FQDN)")
    parser.add_argument("--csv", type=str, help="CSV filename to write output")
    parser.add_argument("--json", type=str, help="JSON filename to write output")
    logger.debug(f'Command line arguments: {parser.parse_args()}')
    
    # Read command line arguments
    arguments = parser.parse_args()
    
    # Prompt for missing arguments
    if arguments.hostname is None:
        host = input("Enter the hostname or IP address of the BIG-IQ: ")
    else:
        host = arguments.hostname

    if arguments.username is None:
        username = input("Enter the username to authenticate with the BIG-IQ: ")
    else:
        username = arguments.username
    
    if arguments.password is None:
        password = getpass.getpass(prompt='Enter the password to authenticate with the BIG-IQ: ', stream=None)
    else:
        password = arguments.password

    # Check for output filenames
    if arguments.csv is not None:
        csv_filename = arguments.csv
        logger.debug(f'CSV filename provided: {csv_filename}')
    else:
        logger.warning('No CSV filename provided')

    if arguments.json is not None:
        json_filename = arguments.json
        logger.debug(f'JSON filename provided: {json_filename}')
    else:
        logger.warning('No JSON filename provided')

    return

def main():
    logger.info('F5 BIG-IQ AS3 Export (includes RBAC) started')
    
    # Parse command line arguments
    logger.debug('Parsing command line arguments') 
    try:
        parse_command_line_arguments()
    except Exception as e:
        logger.error('Error parsing command line arguments: {}'.format(e))
        SystemExit()

    # Retrieve the Application list from the BIG-IQ
    logger.debug('Retrieving Application List from BIG-IQ')
    try:
        as3_config = bigiq_http_get('mgmt/ap/query/v1/tenants/default/reports/ApplicationsList', {'view': 'all'})
        logger.debug(f'Application List Text: {as3_config.text}')
        if as3_config is None:
            logger.error('No response returned from BIG-IQ')
            SystemExit()
        else:
            as3_config_json = as3_config.json()
        logger.debug(f'Application List JSON: {as3_config_json}')
    except Exception as e:
        logger.error(f'Error retrieving AS3 configuration from BIG-IQ at {host}: {e}')
        SystemExit()

    # Retrieve the application count from BIG-IQ
    applicationCount = as3_config_json['result']['totalItems']
    logger.info(f'Retrieved {applicationCount} applications from BIG-IQ at {host}')
    
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
        SystemExit()

    # Retrieve each application service from BIG-IQ
    logger.info('Retrieving Application Services from BIG-IQ')
    for currentApplication in applicationList:
        try:
            applicationServicesResponse = bigiq_http_get('mgmt/ap/query/v1/tenants/default/reports/ApplicationServicesList', {'$appId': currentApplication['id']})
            logger.debug(f'Application Service Text: {applicationServicesResponse.text}')
            applicationServicesResponse_json = applicationServicesResponse.json()
            logger.debug(f'Application Service JSON: {applicationServicesResponse_json}')
        except Exception as e:
            logger.error(f'Error retrieving Application Services from BIG-IQ at {host}: {e}')
            SystemExit()

    # Output the list of applications to a CSV    
    if csv_filename is not None:
        with open(csv_filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['name', 'id', 'selfLink', 'serviceCount'])
            writer.writeheader()
            writer.writerows(applicationList)

    # Output the list of applications to a JSON
    if json_filename is not None:
        with open(json_filename, 'w') as jsonfile:
            json.dump(applicationList, jsonfile, indent=2)

if __name__ == '__main__':
    main()

