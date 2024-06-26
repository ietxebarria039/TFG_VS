import json

#ESTE ARCHIVO SERVIRÁ PARA CREAR LOS MENSAJES JSON PARA 
#COMUNICARSE CON LA API DE OPENSTACK

def mensaje_json_crear_usuario(name, password,description ,email):

    datos = {
        "user": {
            "name": name,
            "password": password,
            "email": email,
            "description": description,
            "options": {
                "ignore_password_expiry": True
            }
        }
    }
    mensaje_json = json.dumps(datos)
    
    return mensaje_json

def mensaje_json_crear_proyecto(name, description):

    datos = {
        "project":{
            "name": name,
            "description": description
        }
    }
    mensaje_json = json.dumps(datos)
    return mensaje_json