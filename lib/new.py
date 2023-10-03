# ---
# Copyright © 2023 ORAE IBC. All Rights Reserved
# This code is licensed under the ORAE License (https://orae.one/license)
# ---

from datetime import datetime
from datetime import timedelta

from lib import log

import firebase_admin
from firebase_admin import credentials
from firebase_admin import messaging

import uuid
import hashlib
import base64
import bcrypt
import sqlite3

DATABASE = './storage/db.sqlite'

class token:
    def session(UserID):
        try:
            key = uuid.uuid4()
            key = base64.b64encode(str(key).encode()).decode()
            date = datetime.now() + timedelta(days=7)
            with sqlite3.connect(DATABASE) as con:
                con.execute('INSERT INTO tokens (Token, UserID, Expiration) VALUES (?,?,?)', (key, UserID, date))
            return key
        except Exception as e:
            log.error(e)
            raise e

    
    def user(username, email):
        try:
            key = username + email
            key = hashlib.sha256(key.encode()).hexdigest()
            key = key + str(uuid.uuid4())
            key = base64.b64encode(key.encode()).decode()
            return key
        except Exception as e:
            log.error(e)
            raise e

class password:
    def encrypt(password):
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password, salt)
            return hashed
        except Exception as e:
            log.error(e)
            raise (e)

class notification:
    def push(MSG_title, MSG_content, UserID):
        cred = credentials.Certificate('storage/storyshare-notifications.json')
        firebase_admin.initialize_app(cred)
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Token FROM FCMToken WHERE UserID = ?', (UserID,))
            device_token = c1.fetchone()
        
        message = messaging.Message(
            notification=messaging.Notification(
                title=MSG_title,
                body=MSG_content
            ),
            token=device_token,
        )
        
        response = messaging.send(message)

        return response;