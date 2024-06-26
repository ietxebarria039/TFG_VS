from functools import wraps
from flask import session, redirect, url_for, flash
import pymysql

connection = pymysql.connect(
    host='localhost',
    user='root',
    password='root',
    database='i2tdb',
    cursorclass=pymysql.cursors.DictCursor
)

def role_required(required_roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('idUser')
            idProject = session.get('idProject')
            print(user_id, idProject)
           
            with connection.cursor() as cursor:
                sql = """
                    SELECT r.Role
                    FROM relation r
                    WHERE r.user_idUser = %s AND r.project_idProject = %s
                """
                cursor.execute(sql, (user_id, idProject))
                result = cursor.fetchone()

                if result and result['Role'] in required_roles:
                    return f(*args, **kwargs)
                else:
                    flash("More permissions nedeed.", "danger")
                    return redirect(url_for('home'))

        return decorated_function
    return decorator
