from flask import Flask, request
import requests

def get_id_member(headers):

    url = 'http://10.98.1.134:5000/v3/roles'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for role in response_json['roles']:
            if role['name'] == 'member':
                idMember =role['id']
                break
            
    return idMember

def get_id_admin(headers):

    url = 'http://10.98.1.134:5000/v3/roles'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for role in response_json['roles']:
            if role['name'] == 'admin':
                idAdmin =role['id']
                break
            
    return idAdmin

def get_id_reader(headers):

    url = 'http://10.98.1.134:5000/v3/roles'
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        response_json = response.json()
        for role in response_json['roles']:
            if role['name'] == 'reader':
                idreader =role['id']
                break
            
    return idreader