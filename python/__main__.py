import csv
import json
import requests

bigiq_address = "192.168.1.100"
username = "admin"
password = "admin"

url = f"https://{bigiq_address}/mgmt/shared/resolver/device-groups/cm-adc-allbigipDevices/devices?$select=address,name,deviceInfo&$filter=deviceInfo/machineId+ne+''"

response = requests.get(url, auth=(username, password), verify=False)
data = json.loads(response.content)

with open('f5_as3_configs.csv', 'w', newline='') as csvfile:
    fieldnames = ['name', 'address', 'machineId', 'as3Config']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for device in data['items']:
        url = f"https://{bigiq_address}/mgmt/shared/iapp/blocks?$filter=deviceReference/address+eq+\'{device['address']}\'"

        response = requests.get(url, auth=(username, password), verify=False)
        data = json.loads(response.content)
        for block in data['items']:
            writer.writerow({
                'name': device['name'],
                'address': device['address'],
                'machineId': device['deviceInfo']['machineId'],
                'as3Config': json.dumps(block['inputProperties'])
            })
