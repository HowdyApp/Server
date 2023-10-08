# ---
# Copyright © 2023 ORAE IBC. All Rights Reserved
# This code is licensed under the ORAE License (https://orae.one/license)
# ---

from flask import Flask
from flask import redirect
from flask import url_for
from flask import request
from flask import jsonify
from flask import send_file
from flask import send_from_directory
from flask_cors import CORS

from lib import new
from lib import log
from lib import get

import os
import psycopg2
import base64
import uuid
import shutil
import dotenv
import datetime
import re

DBUSERNAME = dotenv.get_key('/app/storage/db.key', 'username')
DBPASSWORD = dotenv.get_key('/app/storage/db.key', 'password')
DBHOSTNAME = dotenv.get_key('/app/storage/db.key', 'host')
DBHOSTPORT = dotenv.get_key('/app/storage/db.key', 'port')
DATABASE = f'dbname=main user={DBUSERNAME} password={DBPASSWORD} host={DBHOSTNAME} port={DBHOSTPORT}'

app = Flask(__name__)
CORS(app)
con = psycopg2.connect(DATABASE)

@app.before_request
def beforeRequest():
    log.session(f'Endpoint request --> {request.endpoint}')

class web:
    @app.route('/')
    def index(): return send_file('web/main.html')
    @app.route('/download')
    def download(): return send_file('app/howdy.apk')
    @app.route('/logo')
    def logo(): return send_file('web/howdy.png')
    @app.route('/terms-of-service')
    def tos(): return send_file('app/legal.txt')

class account:
    @app.route('/account/register', methods=['POST'])
    def register():
        data = request.get_json()

        username = data['user']
        mailadrs = data['mail']
        password = new.password.encrypt(data['pasw'])

        if not re.match(r'^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$', mailadrs):
            return jsonify(
                code='regex_error',
                msg='Please enter a valid mail.'
            ), 200

        UserID = new.token.user(username, mailadrs)
        with con.cursor() as cur:
            try:
                cur.execute('INSERT INTO auth (user, mail, pasw, profile, userid) VALUES (%s, %s, %s, %s, %s)', (username, mailadrs, password, "https://avataaars.io/?avatarStyle=Circle", UserID))
                con.commit()
                sessionToken = new.token.session(UserID)
                return jsonify(
                    msg='Account created!',
                    code='Created',
                    token=sessionToken,
                ), 201
            
            except psycopg2.IntegrityError:
                log.error('User is already registered!')
                return jsonify(
                    msg='User is already registered!',
                    code='already_exists'
                ), 400
            
            except Exception as e:
                log.fatal(e)
                return jsonify(
                        msg='There was an unexpected error!',
                        code='error'
                    ), 500

    @app.route('/account/login', methods=['POST'])
    def login():
        try:
            data = request.get_json()
            mail = data['mail']
            pasw = data['pasw']

            with con.cursor() as cur:
                cur.execute('SELECT userid FROM auth WHERE mail = %s', (mail,))
                r1 = cur.fetchone()
                if r1 is not None:
                    r1 = r1[0]
                else: return jsonify(
                    msg='Invalid mail or password!',
                    code='invalid_credentials'
                ), 401

                cur.execute('SELECT pasw FROM auth WHERE mail = %s', (mail,))
                r2 = cur.fetchone()
                if r2 is not None:
                    r2 = r2[0]
                    r2 = get.password.check(pasw, r2)
                    if not(r2): return jsonify(
                        msg='Invalid mail or password!',
                        code='invalid_credentials'
                    ), 401

            sessionToken = new.token.session(r1)
            
            return jsonify(
                msg='Logged in successfully!',
                code='authorized',
                token=sessionToken
            ), 202
        except Exception as e:
            log.fatal(e)
            return jsonify(
                msg='There was an unexpected error!',
                code='error'
            ), 500
    
    @app.route('/account/me', methods=['POST'])
    def me():
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with con.cursor() as cur:
            cur.execute('SELECT user FROM auth WHERE userid = %s', (UserID,))
            r1 = cur.fetchone()[0]
        
        return jsonify(
            name=r1,
            msg='Success!',
        )

    @app.route('/account/delete', methods=['POST'])
    def delete():
        try:
            data = request.get_json()
            pasw = str(data['pasw']).encode('utf-8')
            token = request.headers.get('auth')

            UserID = get.token.session(token)

            if UserID is None:
                return jsonify(
                    msg='Unauthorized!',
                    code='unauthorized',
                ), 401

            with con.cursor() as cur:
                cur.execute('SELECT pasw FROM auth WHERE userid = %s', (UserID,))
                r1 = cur.fetchone()[0]
                r2 = get.password.check(pasw, r1)
                if not(r2): return jsonify(
                    msg='Unauthorized!',
                    code='unauthorized',
                ), 401
        except Exception as e:
            log.fatal(e)
            return jsonify(
                msg='There was an unexpected error!',
                code='error'
            ), 500

        with con.cursor() as cur:
            cur.execute('DELETE FROM auth WHERE userid = %s', (UserID,))
            cur.execute('DELETE FROM friends WHERE User = %s', (UserID,))
            cur.execute('DELETE FROM friends WHERE Friend = %s', (UserID,))
            cur.execute('DELETE FROM tokens WHERE UserID = %s', (UserID,))
            cur.execute('DELETE FROM images WHERE UserID = %s', (UserID,))
            # deepcode ignore PT: <please specify a reason of ignoring this>
            try: shutil.rmtree(f'./images/{UserID}')
            except: ''

        return jsonify(
            msg='Your account is deleted!',
            code='account_deleted',
        ), 202
    
    @app.route('/account/profile/set', methods=['POST'])
    def setProfile():
        data = request.get_json()
        url = data['url']
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        if not re.match(r'^https://avataaars\.io', url): return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with con.cursor() as cur:
            cur.execute('UPDATE auth SET profile = %s WHERE userid = %s', (url, UserID))
        
        return jsonify(
            msg='Profile picture updated!',
            code='profile_updated',
        ), 202

    @app.route('/account/profile/get', methods=['POST'])
    def getProfile():
        data = request.get_json()
        UserID = data['user']

        with con.cursor() as cur:
            cur.execute('SELECT profile FROM auth WHERE user = %s', (UserID,))
            r1 = cur.fetchone()[0]
        
        return jsonify(
            profile=r1,
            msg='Success!',
        ), 200

class user:
    @app.route('/user/search', methods=['POST'])
    def search():
        data = request.get_json()
        user = data['user']

        with con.cursor() as cur:
            cur.execute('SELECT user FROM auth WHERE user LIKE %s', (f'%{user}%',))
            r1 = cur.fetchall()

        return jsonify(
            results=[x[0] for x in r1],
            msg='Success!'
        ), 200

    @app.route('/user/add', methods=['POST'])
    def add():
        data = request.get_json()
        user = data['user']
        friend = data['friend']

        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with con.cursor() as cur:
            cur.execute('SELECT userid FROM auth WHERE user = %s', (friend,))
            r1 = cur.fetchone()
            if r1 is not None:
                r1 = r1[0]
            else: return jsonify(
                msg='User not found!',
                code='user_not_found',
            ), 404

            cur.execute('SELECT User FROM friends WHERE User = %s AND Friend = %s', (UserID, r1))
            r2 = cur.fetchone()
            if r2 is not None: return jsonify(
                msg='Already friends!',
                code='already_friends'
            ), 400

            cur.execute('INSERT INTO friends (User, Friend) VALUES (%s, %s)', (UserID, r1))
            cur.execute('INSERT INTO friends (User, Friend) VALUES (%s, %s)', (r1, UserID))
        
        return jsonify(
            msg='Friend added!',
            code='friend_added'
        ), 202
    
    @app.route('/user/friends', methods=['POST'])
    def friends():
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401

        with con.cursor() as cur:
            cur.execute('SELECT Friend FROM friends WHERE User = %s', (UserID,))
            r1 = cur.fetchall()
        
        friends = [x[0] for x in r1]
        return jsonify(
            friends=friends,
            msg='Success!'
        ), 200

    @app.route('/user/remove', methods=['POST'])
    def remove():
        data = request.get_json()
        friend = data['friend']

        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with con.cursor() as cur:
            cur.execute('SELECT userid FROM auth WHERE user = %s', (friend,))
            r1 = cur.fetchone()
            if r1 is not None:
                r1 = r1[0]
            else: return jsonify(
                msg='User not found!',
                code='user_not_found',
            ), 404

            cur.execute('DELETE FROM friends WHERE User = %s AND Friend = %s', (UserID, r1))
            cur.execute('DELETE FROM friends WHERE User = %s AND Friend = %s', (r1, UserID))
        
        return jsonify(
            msg='Friend removed!',
            code='friend_removed'
        ), 202

    @app.route('/user/change/name', methods=['POST'])
    def changeName():
        data = request.get_json()
        user = data['user']

        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with con.cursor() as cur:
            cur.execute('UPDATE auth SET user = %s WHERE userid = %s', (user, UserID))
        
        return jsonify(
            msg='Username changed!',
            code='username_changed'
        ), 202

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
