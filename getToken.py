import requests
import json

def get_openstack_session_token(auth_url, username, password, domain_name):
    url = f"{auth_url}/auth/tokens"
    
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"name": domain_name},
                        "password": password
                    }
                }
            }
        }
    }

    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    if response.status_code == 201:
        token = response.headers['X-Subject-Token']
        return token
    else:
        raise Exception(f"Failed to obtain token: {response.status_code} - {response.text}")

def get_openstack_project_token(auth_url, username, password, domain_name, project_name):
    url = f"{auth_url}/auth/tokens"
    
    data = {
        "auth": {
            "identity": {
                "methods": ["password"],
                "password": {
                    "user": {
                        "name": username,
                        "domain": {"name": domain_name},
                        "password": password
                    }
                }
            },
            "scope": {
                "project": {
                    "name": project_name,
                    "domain": {"name": domain_name}
                }
            }
        }
    }


    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    if response.status_code == 201:
        token = response.headers['X-Subject-Token']
        return token
    else:
        raise Exception(f"Failed to obtain token: {response.status_code} - {response.text}")


def get_openstack_admin_token(auth_url, username, password, domain_name):
    url = f"{auth_url}/auth/tokens"
    
    data = {
            "auth": {
                "identity": {
                    "methods": ["password"],
                    "password": {
                        "user": {
                            "name": username,
                            "domain": {"name": domain_name},
                            "password": password
                        }
                    }
                },
            "scope": {
                "project": {
                    "name": "admin",
                    "domain": {"name": "default"}
                }
            }
        }
    }
    headers = {
        'Content-Type': 'application/json'
    }

    response = requests.post(url, headers=headers, data=json.dumps(data))
    
    if response.status_code == 201:
       
        token = response.headers['X-Subject-Token']
        return token
    else:
        raise Exception(f"Failed to obtain token: {response.status_code} - {response.text}")