from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import time
from flask import Flask, render_template, request, redirect, url_for, session, send_from_directory
import pymysql.cursors
import bcrypt
import requests
import datetime
from message_creator import *
from getID import *
from getToken import *
from security import *
from required_previous_page import *
from get_VM_info import *
from generateCommand import *
from queries import *

url_identity = 'http://10.98.1.134:5000/v3'
url_compute = 'http://10.98.1.134:8774/v2.1'
url_network = 'http://10.98.1.134:9696'
now = datetime.datetime.now()

app = Flask(__name__)
app.secret_key='123456789'

connection = pymysql.connect(
    host='localhost',
    user='root',
    password='root',
    database='i2tdb',
    cursorclass=pymysql.cursors.DictCursor
)

@app.route('/resize', methods=['POST'])
def resize():
    try:
        id_vm = request.form['idVM']
        
        token = session.get('admin_token')
        if not token:
            raise Exception("Project token is missing in session.")
        
        flavors = get_flavors(url_compute, token)
        
        show_flavors = True
        
        return render_template('project.html', 
                               project_name=session.get('project_name'), 
                               VM_list=session.get('VM_list'), 
                               flavors=flavors, 
                               show_flavors=show_flavors,
                               selected_vm_id=id_vm)
    except Exception as e:
        app.logger.error(f"Error in /resize: {e}")
        return "An error occurred while processing your request. Please try again later.", 500

@app.route('/resize_project', methods=['POST'])
def resize_project():
    try:
        id_vm = request.form['idVM']
        flavor_id = request.form['flavor_id']
        
        resize_instance(id_vm, flavor_id)
        
        return redirect(url_for('project'))
    except Exception as e:
        app.logger.error(f"Error in /resize_project: {e}")
        return "An error occurred while processing your request. Please try again later.", 500

def check_instance_status(instance_id):
    try:
        url = f"{url_compute}/servers/{instance_id}"
        headers = {'X-Auth-Token': session.get('project_token')}
        time.sleep(10)
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data['server']['status']
        else:
            return None
        
    except Exception as e:
        app.logger.error(f"Error checking instance status: {e}")
        return None
    
def resize_instance(id_vm, flavor_id):
    try:
        url = f"{url_compute}/servers/{id_vm}/action"
        headers = {
            'X-Auth-Token': session.get('project_token'),
            'Content-Type': 'application/json'
        }
        data = {
            "resize": {
                "flavorRef": flavor_id
            }
        }
        json_data = json.dumps(data)  # Convertir a JSON
        
        response = requests.post(url, headers=headers, data=json_data)
        
        if response.status_code not in [202, 200]:
          
            raise Exception(f"Failed to resize instance: {response.status_code} - {response.text}")
        time.sleep(10)
        instance_status = check_instance_status(id_vm)
        while instance_status == 'active':
            print("Instance is still active. Waiting...")
              # Esperar 10 segundos antes de volver a verificar
            instance_status = check_instance_status(id_vm)
        instance_id = id_vm  
        confirm_url = f"{url_compute}/servers/{instance_id}/action"
        confirm_data = {
            "confirmResize": None
        }
        confirm_json_data = json.dumps(confirm_data)
            
        confirm_response = requests.post(confirm_url, headers=headers, data=confirm_json_data)
        if confirm_response.status_code not in [204]:  
            raise Exception(f"Failed to confirm instance resize: {confirm_response.status_code} - {confirm_response.text}")
        
        print("Resize and confirmation successful!")
        
    except Exception as e:
        app.logger.error(f"Error in resize_instance: {e}")
        raise

@app.route('/remove_user_from_project', methods=['POST'])
@role_required('admin')
def remove_user_from_project():
    idUser = request.form['idUser']
    idProject = request.form['idProject']
    session_ = requests.Session()
    
    with connection.cursor() as cursor:
        sql = "SELECT Role FROM relation WHERE user_idUser=%s AND project_idProject=%s"
        cursor.execute(sql, (idUser, idProject))
        role = cursor.fetchone()

    if role:
        if role['Role'] == 'admin':
            idRole = get_id_admin(session.get('admin_headers'))
        elif role['Role'] == 'member':
            idRole = get_id_member(session.get('admin_headers'))
        elif role['Role'] == 'visitor':
            idRole = get_id_reader(session.get('admin_headers'))

        if idRole:
            url = f"{url_identity}/projects/{idProject}/users/{idUser}/roles/{idRole}"
            headers = session.get('admin_headers')
            response = session_.delete(url, headers=headers)

            if response.status_code == 204:
                with connection.cursor() as cursor:
                    sql = "DELETE FROM relation WHERE user_idUser=%s AND project_idProject=%s"
                    cursor.execute(sql, (idUser, idProject))
                    connection.commit()

                flash('User removed from project successfully in OpenStack and database.', 'success')
            else:
                flash('Failed to remove user from project in OpenStack.', 'danger')
        else:
            flash('Failed to retrieve role ID from OpenStack.', 'danger')
    else:
        flash('User not found in the project.', 'danger')

    return redirect(url_for('intermedio', idProject=idProject))

@app.route('/add_user_to_project', methods=['GET', 'POST'])
@role_required('admin')
def add_user_to_project():
    session_ = requests.Session()
    if request.method == 'POST':
        idUser = request.form['idUser']
        idProject = request.form['idProject']
        role = request.form['role']
        if role == 'admin':
            idRole = get_id_admin(session.get('admin_headers'))
        elif role == 'member':
            idRole = get_id_member(session.get('admin_headers'))
        elif role == 'visitor':
            idRole = get_id_reader(session.get('admin_headers'))

        print(idRole, idProject, idUser)
        headers=session.get('admin_headers')


        if idRole:
            data = None
            url = url_identity+'/projects/'+idProject+'/users/'+idUser+'/roles/'+idRole
            response2 = session_.put(url,data=data,headers=headers)
            if response2.status_code == 204:
                with connection.cursor() as cursor:
            
                    sql = "INSERT INTO relation (Role, user_idUser, project_idProject) VALUES (%s, %s, %s)"
                    cursor.execute(sql, (role, idUser, idProject))
                    connection.commit()
                    print("Inserted into relation table")

                flash('User added to project successfully in OpenStack.', 'success')
            else:
                flash('Failed to add user to project in OpenStack.', 'danger')
        else:
            flash('Failed to retrieve role ID from OpenStack.', 'danger')

    return redirect(url_for('project'))

@app.route('/intermedio')
def intermedio():
        with connection.cursor() as cursor:
            cursor.execute("SELECT idUser, Username FROM user")
            all_users = cursor.fetchall()

            cursor.execute("SELECT idProject, Name FROM project")
            projects = cursor.fetchall()

            idProject = session.get('idProject')
            print(idProject)
            if idProject:
                sql = """
                    SELECT u.idUser, u.Username, r.Role 
                    FROM user u 
                    JOIN relation r ON u.idUser = r.user_idUser 
                    WHERE r.project_idProject = %s
                """
                cursor.execute(sql, (idProject,))
                project_users = cursor.fetchall()
                
                project_user_ids = {user['idUser'] for user in project_users}
                available_users = [user for user in all_users if user['idUser'] not in project_user_ids]
            else:
                project_users = []
                available_users = all_users
            
            roles = ['admin', 'member', 'visitor']

        return render_template('add_user_to_project.html', users=available_users, project_users=project_users, projects=projects, roles=roles, selected_project=idProject)
    
@app.route('/update_user_role', methods=['POST'])
@role_required('admin')
def update_user_role():
    idUser = request.form['idUser']
    idProject = request.form['idProject']
    newRole = request.form['newRole']
    session_ = requests.Session()

    if newRole == 'admin':
        idRole = get_id_admin(session.get('admin_headers'))
    elif newRole == 'member':
        idRole = get_id_member(session.get('admin_headers'))
    elif newRole == 'visitor':
        idRole = get_id_reader(session.get('admin_headers'))

    if idRole:
        url = f"{url_identity}/projects/{idProject}/users/{idUser}/roles/{idRole}"
        headers = session.get('admin_headers')
        response = session_.put(url, headers=headers)

        if response.status_code == 204:
            with connection.cursor() as cursor:
                sql = "UPDATE relation SET Role=%s WHERE user_idUser=%s AND project_idProject=%s"
                cursor.execute(sql, (newRole, idUser, idProject))
                connection.commit()

            flash('User role updated successfully in OpenStack and database.', 'success')
        else:
            flash('Failed to update user role in OpenStack.', 'danger')
    else:
        flash('Failed to retrieve role ID from OpenStack.', 'danger')

    return redirect(url_for('intermedio', idProject=idProject))

@app.route('/joinProject', methods=['GET'])
def join_project():
    headers = session.get('admin_headers')
    url = url_identity+'/projects'
    response = requests.get(url, headers=headers)
    projects = []
    if response.status_code == 200:
        projects = response.json().get('projects', [])

    return render_template('joinProject.html', projects=projects)

@app.route('/send_email', methods=['POST'])
def send_email():
    project_name = request.form['project_name']
    project_description = request.form['project_description']
    idUser = session.get('idUser')

    with connection.cursor() as cursor:
        cursor.execute("SELECT email FROM user WHERE idUser = %s", (idUser,))
        user = cursor.fetchone()

    if user:
        username = session.get('username')
        emisor = user['email']
        receptor = 'ibon2001@gmail.com'
        subject = f"Join Project Request: {project_name}"
        body = f"User {username} wants to join the project {project_name}.\n\nDescription: {project_description}"

        msg = MIMEMultipart()
        msg['From'] = emisor
        msg['To'] = receptor
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        try:
            # Configura tu servidor de correo
            smtp_server = 'smtp.gmail.com'
            smtp_port = 587
            smtp_user = 'ibonetxebarria@bilbokoeskolapioak.org'
            smtp_password = '04010401'

            server = smtplib.SMTP(smtp_server, smtp_port)
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(emisor, receptor, msg.as_string())
            server.quit()
        except Exception as e:
            return str(e)

    return redirect(url_for('home'))

@app.route('/delete_VM',  methods=['GET', 'POST'])
@role_required(['admin','member'])
def delete_VM():
    if request.method == 'POST':
        idVM = request.form['idVM']
        url = url_compute+'/servers/'+idVM
        headers = {'Content-Type': 'application/json', 'X-Auth-Token': session.get('project_token')}
        response = requests.delete(url, headers=headers)
        if response.status_code == 204:
            
            idProject = session.get('idProject')
            idUser = session.get('idUser')
            insert_command(url+'/delete',idProject,idUser)
            return redirect(url_for('project'))
        else:
            error_message = response.json().get('error', 'Unknown error')
            return render_template('error.html', error_message=error_message)

@app.route('/create_VM',  methods=['GET', 'POST'])
def create_VM():
    if request.method == 'POST':
        instance_name = request.form['instance_name']
        image_id = request.form['image_id']
        flavor_id = request.form['flavor_id']
        network_id = request.form['network_id']
        project_token = session.get('project_token')
        # Crear la instancia
        
        idProject = session.get('idProject')
        idUser = session.get('idUser')

        insert_command(url_compute,idProject,idUser)
        instance = create_instance(url_compute, project_token, instance_name, image_id, flavor_id, network_id)
        return redirect(url_for('project'))
    return render_template('create_VM', instance=instance)

@app.route('/fill_VM_data',  methods=['GET', 'POST'])
def fill_VM_data():
    project_name = session.get('project_name')
    project_token = session.get('project_token')
    
    flavors = get_flavors(url_compute, project_token)
    images = get_images(url_compute, project_token)
    networks = get_networks(url_network, project_token)
    all_flavor_info = []

    for flavor in flavors:
        flavor_id = flavor['id']
        flavor_name = flavor['name']
        disk = flavor['disk']
        ram = flavor['ram']
        vcpus = flavor['vcpus']
        flavor_detail = (flavor_name, flavor_id, "disk:"+str(disk), "RAM:"+str(ram), "VCPU:"+str(vcpus))
        all_flavor_info.append(flavor_detail)
       

    network_subnet_pairs = []
    
    for network in networks:
        network_name = network['name']
        network_id = network['id']
        for subnet_id in network['subnets']:
            subnet = get_subnet(url_network, project_token, subnet_id)
            subnet_name = subnet['subnet']['name']
            cidr = subnet['subnet']['cidr']
            gateway_ip = subnet['subnet']['gateway_ip']
            pair = (
                network_name,
                subnet_name,
                cidr,
                gateway_ip,
                network_id
            )
            network_subnet_pairs.append(pair)
    
    return render_template('new_VM.html', project_name=project_name, all_flavors_info=all_flavor_info, images=images, network_subnet_pairs=network_subnet_pairs)

@app.route('/add_network', methods=['GET', 'POST'])
@role_required(['admin','member'])
def add_network():
    if request.method == 'POST':
        # Network details
        network_name = request.form['name']
        admin_state_up = request.form.get('admin_state_up') == 'on'
        shared = request.form.get('shared') == 'on'
        external = request.form.get('external') == 'on'

        # Subnet details
        subnet_name = request.form['subnet_name']
        cidr = request.form['cidr']
        ip_version = int(request.form['ip_version'])
        gateway_ip = request.form.get('gateway_ip')

        idProject = session.get('idProject')
        # Network data
        network_data = {
            "network": {
                "name": network_name,
                "admin_state_up": admin_state_up,
                "shared": shared,
                "router:external": external,
                "idProject": idProject
            }
        }

        headers = session.get('admin_headers')

        # Create the network
        response_network = requests.post(url_network+'/v2.0/networks', headers=headers, data=json.dumps(network_data))
        
        if response_network.status_code == 201:
            network_id = response_network.json()['network']['id']
            flash('Network created successfully.', 'success')
            
            # Subnet data
            subnet_data = {
                "subnet": {
                    "name": subnet_name,
                    "network_id": network_id,
                    "ip_version": ip_version,
                    "cidr": cidr,
                }
            }

            if gateway_ip:
                subnet_data["subnet"]["gateway_ip"] = gateway_ip

            # Create the subnet
            response_subnet = requests.post(url_network + '/v2.0/subnets', headers=headers, data=json.dumps(subnet_data))
            
            if response_subnet.status_code == 201:
                flash('Subnet created successfully.', 'success')
            else:
                flash(f"Error creating subnet: {response_subnet.status_code}, {response_subnet.text}", 'danger')
        else:
            flash(f"Error creating network: {response_network.status_code}, {response_network.text}", 'danger')

        return redirect(url_for('admin'))

    return render_template('add_network.html')


@app.route('/add_flavor', methods=['GET','POST'])
@role_required(['admin','member'])
def add_flavor():
    session['last_page'] = 'add_flavor'

    if request.method == 'POST':
        flavor_name = request.form['name']
        vcpus = request.form['vcpus']
        ram = request.form['ram']
        disk = request.form['disk']

        data = {
            "flavor": {
                "name": flavor_name,
                "ram": int(ram),
                "vcpus": int(vcpus),
                "disk": int(disk)
            }
        }
        print(json.dumps(data))
        headers = session.get('admin_headers')
        print(headers)
        url = url_compute + '/flavors'
        
        
        response = requests.post(url, headers=headers, data=json.dumps(data))

        if response.status_code == 200 or response.status_code == 201:
            return redirect(url_for('admin'))
        else:
            return f"Error: {response.status_code}, {response.text}"
    
    return render_template('add_flavor.html')

@app.route('/project', methods=['GET', 'POST'])
def project():
    VM_list = []
    session['last_page'] = 'project'
    if request.method == 'POST':
        project_name = request.form['project_name']
        session['project_name'] = project_name
        idProject = request.form['idProject']
        print(idProject)
        session['idProject'] = idProject
    else:
        project_name = session.get('project_name')
        idProject = session.get('idProject')
        idUser = session.get('idUser')

    project_token = get_openstack_project_token(url_identity, session['username'], session['password'], 'default', project_name)
    session['project_token'] = project_token

    url = url_compute + '/servers/detail'
    idUser = session.get('idUser')
    current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with connection.cursor() as cursor:
        sql2 = ("UPDATE project SET Last_access = %s WHERE idProject = %s")
        cursor.execute(sql2, (current_time, idProject))
        connection.commit()

        headers = {'Content-Type': 'application/json', 'X-Auth-Token': project_token}
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            insert_command(url, idProject, idUser)
            VM_list = response.json()['servers']
            session['VM_list'] = VM_list

            url_flavors = url_compute + '/flavors/detail'
            response_flavors = requests.get(url_flavors, headers=headers)
            if response_flavors.status_code == 200:
                flavors = response_flavors.json()['flavors']
                flavor_dict = {flavor['id']: flavor['name'] for flavor in flavors}
            else:
                flavor_dict = {}

            for vm in VM_list:
                flavor_id = vm['flavor']['id']
                vm['flavor_name'] = flavor_dict.get(flavor_id, 'Unknown')
        
    return render_template('project.html', project_name=project_name, VM_list=VM_list)

@app.route('/delete_project', methods=['GET', 'POST'])
@role_required(['admin','member'])
def delete_project():
    if request.method == 'POST':
        idProject = request.form['idProject']
        url = url_identity + '/projects/' + idProject

        response = requests.delete(url, headers=session.get('admin_headers'))

        if response.status_code == 204:
            try:
                with connection.cursor() as cursor:
                    sql_relation = "DELETE FROM relation WHERE project_idProject = %s"
                    cursor.execute(sql_relation, (idProject,))

                    sql_command = "DELETE FROM command WHERE project_idProject = %s"
                    cursor.execute(sql_command, (idProject,))

                    sql_project = "DELETE FROM project WHERE idProject = %s"
                    cursor.execute(sql_project, (idProject,))

                    connection.commit()

                return redirect(url_for('select_project'))
            except Exception as e:
                print(f"Error deleting the project in the database: {str(e)}")
                return 'Could not delete the project in the database'
        else:
            return 'Could not delete the project in OpenStack'

@app.route('/edit_project', methods= ['GET', 'POST'])
@role_required(['admin','member'])
def edit_project():
    if request.method == 'POST':
        idProject = request.form['idProject']
        session['idProject'] = idProject
      
    return render_template('edit_project.html', idProject=idProject)

@app.route('/confirm_edit', methods=['GET','POST'])
def confirm_edit():

    if request.method =='POST':
        new_name = request.form['new_name']
        new_description = request.form['new_description']
        data =mensaje_json_crear_proyecto(new_name, new_description)
        print(data)
        url = url_identity+'/projects/'+session.get('idProject')
        headers = session.get('admin_headers')
        print(url)
#HAS CAMBIADO EL NOMNRE PERO NO ESTAS ACTUALIZANDOLO PARA VERLO, ES POR EL MYSQL
        response = requests.patch(url,headers=headers, data=data)
        if response.status_code == 200:
            try:
                with connection.cursor() as cursor:
                    sql = "UPDATE project SET Name = %s, Description = %s WHERE idProject = %s"
                    cursor.execute(sql, (new_name, new_description, session.get('idProject')))
                    connection.commit()
                return redirect(url_for('home'))
            except Exception as e:
                print(f"Error updating the project in the database: {str(e)}")
                return 'Could not edit the project in the database'
        else:
            return 'Could not edit the project in OpenStack'
        
@app.route('/select_project', methods=['GET', 'POST'])
def select_project():
    session['last_page'] = 'select_project'

    try:
        idUser = session.get('idUser')
        projects = []

        with connection.cursor() as cursor:
            sql = """SELECT p.idProject, p.Name FROM project p JOIN relation r ON p.idProject = r.project_idProject WHERE r.user_idUser = %s"""
            cursor.execute(sql, (idUser,))
            projects = cursor.fetchall()

        token = session.get('admin_token')
        if not token:
            raise Exception("Admin token is missing in session.")
        
        flavors = get_flavors(url_compute, token)

        show_flavors = 0
        return render_template('listarProyectos.html', username=session.get('username'), projects=projects, flavors=flavors, show_flavors=show_flavors)
    except Exception as e:
        app.logger.error(f"Error in /select_project: {e}")
        return "An error occurred while processing your request. Please try again later.", 500
    
@app.route('/create_project', methods=['GET', 'POST'])
@role_required(['admin','member'])
def create_project(): 
    session['last_page'] = 'create_project'

    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        data = mensaje_json_crear_proyecto(name,description)
        session_ = requests.Session()
        url = url_identity+'/projects'
        
        headers = session.get('admin_headers')
        
        response = session_.post(url,headers=headers, data=data)
        
        if response.status_code == 201:
            respuesta_json = response.json()
            idProject = respuesta_json['project']['id']
            idUser = session.get('idUser')
            with connection.cursor() as cursor:
                sql = 'INSERT INTO project (idProject, Name, Description, Creation_date, Last_access, VM_CPU, VM_RAM, VM_Count, NET_Count, NET_Subnet_Count, NET_Ports_Count) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)'
                cursor.execute(sql, (idProject, name, description, now, now, 10, 10, 10, 10, 10, 10))
                connection.commit()

                #RELACIÓN ENTRE USERS Y PROJECTS TANTO EN OS COMO EN SQL
                idRole = get_id_member(session['admin_headers'])
                
                url = url_identity+'/projects/'+idProject+'/users/'+idUser+'/roles/'+idRole
                
                response2 = session_.put(url,headers=session['admin_headers'], data=data)
                
                if response2.status_code == 204:
                    sql_relation = 'INSERT INTO relation (Role, user_idUser, project_idProject) VALUES (%s, %s, %s)'
                    cursor.execute(sql_relation, ("admin",idUser, idProject))
                    connection.commit() 
                    session['project_name'] = name
                    insert_command(url,idProject,idUser)
                    return redirect(url_for('select_project'))           
    return render_template('createProject.html')

@app.route('/login', methods=['GET', 'POST'])
def login(): 
    session['last_page'] = 'login'    

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with connection.cursor() as cursor:
            sql = "SELECT idUser, Password FROM user WHERE Username=%s"
            cursor.execute(sql, (username,))
            result = cursor.fetchone()
            if result:
                hashed_password = result['Password'].encode('utf-8')
                if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
                    session['username'] = username
                    session['idUser'] = result['idUser']
                    session['password'] = password
                    session_token = get_openstack_session_token(url_identity, username, password,'default')
                    session_headers = {'X-Auth-Token': session_token, 'Content-Type': 'Application/json'}
                    session['session_headers'] = session_headers
                    insert_login_command('login done',session.get('idUser'))
                    
                   
                    admin_token = get_openstack_admin_token(url_identity,username='admin',password='d9c424ac31bb2e722793',domain_name='default')
                    admin_headers = {'X-Auth-Token': admin_token, 'Content-Type': 'application/json'}
                    session['admin_token'] = admin_token
                    session['admin_headers'] = admin_headers
                    return redirect(url_for('home'))
        return "Incorrect username or password"
    return render_template('login.html')

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    session['last_page'] = 'register'

    if request.method == 'POST':
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']
        description = request.form['description']
        email = request.form['email']
        if password1 == password2:
            session_ = requests.Session()
            data = mensaje_json_crear_usuario(username, password1,description,email)
            url=url_identity+'/users'
            admin_token = get_openstack_admin_token(url_identity,username='admin',password='d9c424ac31bb2e722793',domain_name='default')
            admin_headers = {'X-Auth-Token': admin_token, 'Content-Type': 'Application/json'}
            response = session_.post(url, headers=admin_headers, data=data)
            session['admin_token'] = admin_token
            session['admin_headers'] = admin_headers
            if response.status_code == 201:
                respuesta_json = response.json()
                idUser = respuesta_json['user']['id']
                session['idUser'] = idUser
                hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
                with connection.cursor() as cursor:
                    sql = "INSERT INTO user (idUser, Username, Password, email) VALUES (%s, %s, %s, %s)"
                    cursor.execute(sql, (idUser, username, hashed_password, email))
                    connection.commit()
                    return redirect(url_for('login'))
                
    return render_template('registro.html') 

@app.route('/admin', methods=['GET', 'POST'])
@role_required('admin')
@require_previous_page('project')
def admin():
    session['last_page'] = 'admin'

    return render_template('admin.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))


@app.route('/home', methods=['GET', 'POST'])
def home():
    session['last_page'] = 'home'

    username = session.get('username')
    return render_template('home.html', username=username)

@app.route('/')
def index():
    session['last_page'] = 'index'

    return  render_template('index.html')

# if __name__ == '__main__':
#     app.run(host='0.0.0.0', port=5001)


if __name__ == '__main__':
    app.run(debug=True ,port=5001)
