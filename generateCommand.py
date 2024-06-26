import datetime
import pymysql


connection = pymysql.connect(
    host='localhost',
    user='root',
    password='root',
    database='i2tdb',
    cursorclass=pymysql.cursors.DictCursor
)


def insert_command(command, project_id, user_id):
    try:
        with connection.cursor() as cursor:
            sql = """
            INSERT INTO `command` (`Command`, `Time`, `project_idProject`, `user_idUser`)
            VALUES (%s, %s, %s, %s)
            """
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(sql, (command, current_time, project_id, user_id))
            connection.commit()
    except Exception as e:
        print(f"Error inserting command: {e}")
    
def insert_login_command(command, user_id):
    try:
        with connection.cursor() as cursor:
            sql = """
            INSERT INTO `command` (`Command`, `Time`,`user_idUser`)
            VALUES (%s, %s, %s)
            """
            current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute(sql, (command, current_time, user_id))
            connection.commit()
    except Exception as e:
        print(f"Error inserting command: {e}")
    