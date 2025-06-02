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

if not os.path.exists('outputs'):
    os.makedirs('outputs')

# Configure logging
logging.basicConfig(level=logging.DEBUG,
                    filename='logs/f5_as3.log',
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger(__name__)

# Configure console logging
console = logging.StreamHandler()
console.setLevel(logging.INFO)
console.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
logger.addHandler(console)

# Log an instantiation message
logger.info('<----- F5 BIG-IQ AS3 Export (includes RBAC) initiated ----->')

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
        terminate_process()
    try:
        auth_token = response.json()['token']['token']
        auth_token_expiry = response.json()['token']['exp']
        logger.debug(f'Auth token retrieved with expiration of {auth_token_expiry} epoch time')
    except KeyError as e:
        logger.error(f'Error retrieving auth token: JSON key not found in response: {response.text} - {e}')
        terminate_process()
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
        terminate_process()
    logger.debug(f'BIG-IP API Response: {response.text}')
    return response

def parse_command_line_arguments():
    # Define BIG-IQ environment variables
    global username
    global password
    global host
    global csvFilename
    global jsonFilename
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description="Collect AS3 configurations from a BIG-IQ and output them to a CSV or JSON file"
    )
    parser.add_argument("--username", type=str, help="Username for BIG-IQ")
    parser.add_argument("--password", type=str, help="Password for BIG-IQ user")
    parser.add_argument("--hostname", type=str, help="BIG-IQ host (IP/FQDN)")
    parser.add_argument("--csv", type=str, help="CSV filename to write output")
    parser.add_argument("--json", type=str, help="JSON filename to write output")
    
    # Read command line arguments
    arguments = parser.parse_args()
    
    # Prompt for missing arguments
    if arguments.hostname is None:
        host = input("Enter the hostname or IP address of the BIG-IQ: ")
    else:
        host = arguments.hostname
    logger.debug(f'BIG-IQ hostname provided: {host}')

    if arguments.username is None:
        username = input("Enter the username to authenticate with the BIG-IQ: ")
    else:
        username = arguments.username
    logger.debug(f'Username provided: {username}')
    
    if arguments.password is None:
        password = getpass.getpass(prompt='Enter the password to authenticate with the BIG-IQ: ', stream=None)
    else:
        password = arguments.password
    logger.debug(f'Password provided; not logged due to security best practices')
    
    # Check for output filenames
    if arguments.csv is not None:
        csvFilename = arguments.csv
        logger.debug(f'CSV filename provided: {csvFilename}')
    else:
        logger.warning('No CSV filename provided')
        csvFilename = None

    if arguments.json is not None:
        jsonFilename = arguments.json
        logger.debug(f'JSON filename provided: {jsonFilename}')
    else:
        logger.warning('No JSON filename provided')
        jsonFilename = None
    
    return host, username, password, arguments.csv, arguments.json

def terminate_process(msg=None):
    if msg is not None:
        logger.warning(f'{msg}')
    logger.info('<----- F5 BIG-IQ AS3 Export (includes RBAC) ended ----->')
    SystemExit()
        
def main():
    logger.info('F5 BIG-IQ AS3 Export (includes RBAC) started')
    
    # Parse command line arguments
    logger.debug('Parsing command line arguments') 
    try:
        host, username, password, csvFilename, jsonFilename = parse_command_line_arguments()
    except Exception as e:
        logger.error('Error parsing command line arguments: {}'.format(e))
        terminate_process()

    # Retrieve the Application list from the BIG-IQ
    logger.debug('Retrieving Application List from BIG-IQ')
    try:
        as3_config = bigiq_http_get('mgmt/ap/query/v1/tenants/default/reports/ApplicationsList', {'view': 'all'})
        logger.debug(f'Application List Text: {as3_config.text}')
        if as3_config is None:
            logger.error('No response returned from BIG-IQ')
            terminate_process()
        else:
            as3_config_json = as3_config.json()
        logger.debug(f'Application List JSON: {as3_config_json}')
    except Exception as e:
        logger.error(f'Error retrieving AS3 configuration from BIG-IQ at {host}: {e}')
        terminate_process()

    # Retrieve the application count from BIG-IQ
    applicationCount = as3_config_json['result']['totalItems']
    logger.info(f'Retrieved {applicationCount} applications from BIG-IQ at {host}')
    
    # Retrieve all AS3 declarations from BIG-IQ
    as3_inventory = bigiq_http_get('/mgmt/shared/appsvcs/declare', {})
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
        terminate_process()

    # Retrieve each application service from BIG-IQ
    logger.info('Retrieving Application Services from BIG-IQ')
    applicationServiceList = []
    for currentApplication in applicationList:
        try:
            applicationServicesResponse = bigiq_http_get('mgmt/ap/query/v1/tenants/default/reports/ApplicationServicesList', {'$appId': currentApplication['id']})
            currentApplicationServiceList = applicationServicesResponse.json()['result']['items']
        except Exception as e:
            logger.error(f'Error retrieving Application Services from BIG-IQ at {host}: {e}')
            terminate_process()
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
                            currentApplicationServiceExport['tenantName'] = currentApplicationService['name'].split('_')[0]
                            currentApplicationServiceExport['applicationName'] = currentApplicationService['name'].split('_', 1)[1:][0]
                            logger.debug(f'Application service {currentApplicationService["name"]} is AS3; adding AS3 declaration')
            else:
                logger.debug(f'Application service {currentApplicationService["name"]} is not AS3; skipping')
            applicationServiceList.append(currentApplicationServiceExport)

    # Output the list of applications to a CSV    
    logger.info('Outputting Application List to CSV')
    if csvFilename is not None:
        # If the file already exists, append a timestamp to the filename
        csvFilename = 'outputs/' + csvFilename
        with open(csvFilename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=['parentApplication', 'parentApplicationId', 'parentApplicationSelfLink', 'name', 'id', 'globalAppId', 'status', 'health', 'activeAlerts', 'enhancedAnalytics', 'deploymentType', 'AS3Declaration', 'tenantName', 'applicationName'])
            writer.writeheader()
            writer.writerows(applicationServiceList)
            logger.debug(f'Output to {csvFilename}: Application List CSV: {applicationList}')
    else:
        logger.info('Skipping CSV output as no filename was provided')    
    
    # Output the list of applications to a JSON
    logger.info('Outputting Application List to JSON')
    if jsonFilename is not None:
        jsonFilename = 'outputs/' + jsonFilename
        with open(jsonFilename, 'w') as jsonfile:
            json.dump(applicationServiceList, jsonfile, indent=2)
            logger.debug(f'Output to {jsonFilename}: Application List JSON: {applicationList}')

    # Export RBAC Roles to JSON
    logger.info('Exporting RBAC Roles to JSON')
    rbacRoles = bigiq_http_get('mgmt/shared/authorization/roles', {})
    with open('outputs/rbac_roles.json', 'w') as jsonfile:
        json.dump(rbacRoles.json(), jsonfile, indent=2)
        logger.debug(f'Output to outputs/rbac_roles.json: RBAC Roles JSON: {rbacRoles.json()}')
        
    # Export RBAC Role Types to JSON
    rbacRoleTypes = bigiq_http_get('mgmt/shared/authorization/role-types', {"$filter": "isPublic eq 'true' and isBuiltIn eq 'false'"})
    with open('outputs/rbac_role_types.json', 'w') as jsonfile:
        json.dump(rbacRoleTypes.json(), jsonfile, indent=2)
        logger.debug(f'Output to outputs/rbac_role_types.json: RBAC Role Types JSON: {rbacRoleTypes.json()}')
        
    # Export RBAC Resource Groups
    rbacResourceGroups = bigiq_http_get('mgmt/shared/authorization/resource-groups', {"$filter": "isPublic eq 'true' and isBuiltIn eq 'false'"})
    with open('outputs/rbac_resource_groups.json', 'w') as jsonfile:
        json.dump(rbacResourceGroups.json(), jsonfile, indent=2)
        logger.debug(f'Output to outputs/rbac_resource_groups.json: RBAC Resource Groups JSON: {rbacResourceGroups.json()}')
        
    # Export RBAC Users
    rbacUsers = bigiq_http_get('/mgmt/shared/authz/users', {})
    with open('outputs/rbac_users.json', 'w') as jsonfile:
        json.dump(rbacUsers.json(), jsonfile, indent=2)
        logger.debug(f'Output to outputs/rbac_users.json: RBAC Users JSON: {rbacUsers.json()}')
        
    # Export RBAC Groups
    rbacUserGroups = bigiq_http_get('mgmt/shared/authn/providers/local/groups', {})
    with open('outputs/rbac_user_groups.json', 'w') as jsonfile:
        json.dump(rbacUserGroups.json(), jsonfile, indent=2)
        logger.debug(f'Output to outputs/rbac_user_groups.json: RBAC User Groups JSON: {rbacUserGroups.json()}')
        
if __name__ == '__main__':
    main()
    terminate_process()
