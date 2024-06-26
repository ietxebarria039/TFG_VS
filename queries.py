

import pymysql


connection = pymysql.connect(
    host='localhost',
    user='root',
    password='root',
    database='i2tdb',
    cursorclass=pymysql.cursors.DictCursor
)

def get_users_from_database():
    with connection.cursor() as cursor:
        sql = "SELECT Username FROM user"
        cursor.execute(sql)
        return cursor.fetchall()

def get_projects_from_database():
     with connection.cursor() as cursor:
        sql = "SELECT Name FROM project"
        cursor.execute(sql)
        return cursor.fetchall()
