import json
import requests



def get_images(url_compute, token):
    url = f"{url_compute}/images"
    headers = {'X-Auth-Token': token}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['images']
    else:
        raise Exception(f"Failed to get images: {response.status_code} - {response.text}")



def get_flavors(url_compute, token):
    url = f"{url_compute}/flavors/detail"
    headers = {'X-Auth-Token': token}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['flavors']
    else:
        raise Exception(f"Failed to get flavors: {response.status_code} - {response.text}")


def get_networks(url_network, token):
    url = f"{url_network}/v2.0/networks"
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': token}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()['networks']
    else:
        raise Exception(f"Failed to get networks: {response.status_code} - {response.text}")

def get_subnet(url_network, project_token, subnet_id):
    url = f"{url_network}/v2.0/subnets/{subnet_id}"
    headers = {
        'Content-Type': 'application/json',
        'X-Auth-Token': project_token
    }
    response = requests.get(url, headers=headers)
    return response.json()

def create_instance(url_compute, token, name, image_id, flavor_id, network_id):
    url = f"{url_compute}/servers"
    headers = {'Content-Type': 'application/json', 'X-Auth-Token': token}
    data = {
        "server": {
            "name": name,
            "imageRef": image_id,
            "flavorRef": flavor_id,
            "networks": [{"uuid": network_id}]
        }
    }
    response = requests.post(url, headers=headers, data=json.dumps(data))
    if response.status_code == 202:
        return response.json()['server']
    else:
        raise Exception(f"Failed to create instance: {response.status_code} - {response.text}")

