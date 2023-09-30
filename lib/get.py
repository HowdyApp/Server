from lib import log
import sqlite3
from datetime import datetime
import bcrypt

DATABASE = './storage/db.sqlite'

class token:
    def session(key):
        try:
            with sqlite3.connect(DATABASE) as con:
                c1 = con.execute('SELECT UserID, Expiration FROM tokens WHERE Token = ? LIMIT 1', (key,))
                r1 = c1.fetchone()
                if r1:
                    user_id, expiration_date_str = r1
                    #! Not needed because of that we are implementing a MOBILE app.
                    # expiration_date_str = expiration_date_str.split('.')[0]
                    # expiration_date = datetime.strptime(expiration_date_str, "%Y-%m-%d %H:%M:%S")
                    # if expiration_date > datetime.now():
                    return user_id
                return None
        except Exception as e:
            log.error(e)
            raise e

class password:
    def check(password, database):
        try:
            if not isinstance(password, (str, bytes)):
                raise ValueError("The password must be a string or bytes")
            if not isinstance(database, (str, bytes)):
                raise ValueError("The database-pw must be a string or bytes")

            if isinstance(password, str):
                password = password.encode()
            if isinstance(database, str):
                database = database.encode()

            return bcrypt.hashpw(password, database)
        except Exception as e:
            raise e
