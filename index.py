# ---
# Copyright © 2023 ORAE IBC. All Rights Reserved
# This code is licensed under the ORAE License (https://orae.one/license)
# ---

from flask import Flask
from flask import request
from flask import jsonify
from flask import send_file
from flask import send_from_directory
from flask_cors import CORS

from lib import new
from lib import log
from lib import get

import os
import sqlite3
import base64
import uuid
import json
import shutil
import dotenv
import datetime

DATABASE = './storage/db.sqlite'

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return send_file('web/main.html')

@app.route('/download')
def download():
    return send_file('app/storyshare.apk')

@app.route('/release')
def releases():
    file = r'build'
    return jsonify(
        serverRelease = dotenv.get_key(file, 'vServer'),
        clientRelease = dotenv.get_key(file, 'vClient')
    ), 200

class home:
    @app.route('/home', methods=['GET'])
    def home():
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if(UserID is None): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Friend FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
            c2 = con.execute('SELECT User FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
            r1 = c1.fetchall() + c2.fetchall()
            friends = [row[0] for row in r1]
            pairs = []

            for friend in friends:
                c3 = con.execute('SELECT ImageID FROM images WHERE UserID = ?', (friend,))
                r3 = c3.fetchall()
                for image_row in r3:
                    pairs.append(f"{friend}/{image_row[0]}")
    
        return jsonify(
            code = 'success',
            msg = 'Loaded all friends!',
            images=pairs
        ), 200

    @app.route('/home/<friend>/<image>')
    def image(friend, image):
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401

        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Friend FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
            r1 = c1.fetchone()
            if (r1): r1 = True
            else: r1 = False
            if r1 is False: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401

        pathdir = f'images/{friend}'
        pathimg = f'{image}.jpg'

        try:
            return send_from_directory(pathdir, pathimg)
        except FileNotFoundError:
            return jsonify(code='dne', msg='Bestaat niet!')


class account:
    @app.route('/account/register', methods=['POST'])
    def register():
        data = request.get_json()

        username = data['user']
        mailadrs = data['mail']
        password = new.password.encrypt(data['pasw'])

        UserID = new.token.user(username, mailadrs)
        with sqlite3.connect(DATABASE) as con:
            try:
                con.execute('INSERT INTO auth (user, mail, pasw, userid) VALUES (?, ?, ?, ?)', (username, mailadrs, password, UserID))
                con.commit()
                sessionToken = new.token.session(UserID)
                return jsonify(
                    msg='Account created!',
                    code='Created',
                    token=sessionToken,
                ), 201
            
            except sqlite3.IntegrityError:
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

            with sqlite3.connect(DATABASE) as con:
                c1 = con.execute('SELECT userid FROM auth WHERE mail = ?', (mail,))
                c2 = con.execute('SELECT pasw FROM auth WHERE mail = ?', (mail,))
                r1 = c1.fetchone()
                if r1 is not None:
                    r1 = r1[0]
                else: return jsonify(
                    msg = 'Invalid mail or password!',
                    code = 'invalid_credentials'
                ), 401
                    

                r2 = (c2.fetchone())[0]

                r2 = get.password.check(pasw, r2)
                if not(r2): return jsonify(
                    msg = 'Invalid mail or password!',
                    code = 'invalid_credentials'
                ), 401

            sessionToken = new.token.session(r1)
            
            return jsonify(
                msg = 'Logged in successfully!',
                code = 'authorized',
                token = sessionToken
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
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
                c1 = con.execute('SELECT user FROM auth WHERE UserID = ?', (UserID,))
                r1 = (c1.fetchone())[0]
        
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
                    msg = 'Unauthorized!',
                    code = 'unauthorized',
                ), 401
            
            
            with sqlite3.connect(DATABASE) as con:
                c1 = con.execute('SELECT pasw FROM auth WHERE userid = ?', (UserID,))
                r1 = (c1.fetchone())[0]
                r2 = get.password.check(pasw, r1)
                if not(r2): return jsonify(
                    msg = 'Unauthorized!',
                    code = 'unauthorized',
                ), 401
        except Exception as e:
            log.fatal(e)
            return jsonify(
                msg='There was an unexpected error!',
                code='error'
            ), 500

        with sqlite3.connect(DATABASE) as con:
            con.execute('DELETE FROM auth WHERE userid = ?', (UserID,))
            con.execute('DELETE FROM friends WHERE User = ?', (UserID,))
            con.execute('DELETE FROM friends WHERE Friend = ?', (UserID,))
            con.execute('DELETE FROM tokens WHERE UserID = ?', (UserID,))
            con.execute('DELETE FROM images WHERE UserID = ?', (UserID,))
            try: shutil.rmtree(f'./images/{UserID}')
            except: ''

        return jsonify(
            msg = 'Your account is deleted!',
            code = 'account_deleted',
        ), 202

class camera:
    @app.route('/cam/new', methods=['POST'])
    def new():
        data = request.get_json()
        image = data['img'].encode()
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if(UserID is None): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        
        ImageID = uuid.uuid4()
        ImageID = f'{ImageID}'
        path = f'./images/{UserID}/{ImageID}.jpg'

        with sqlite3.connect(DATABASE) as con:
            con.execute('INSERT INTO images (UserID, imageID, path) VALUES (?, ?, ?)', (UserID, ImageID, path))

        directory = os.path.dirname(path)
        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(path, "wb") as ws:
            ws.write(base64.decodebytes(image))
            
        return jsonify(
            msg = 'The image is uploaded successfully!',
            code = 'image_upload_success',
        ), 200

class friends:
    @app.route('/friends/add', methods=['POST'])
    def add():
        data = request.get_json()
        Friend = data['friend']
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if(UserID is None): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT userid FROM auth WHERE user = ?', (Friend,))
            r1 = (c1.fetchone())
            if r1 == None: return jsonify(
                msg="Unauthorized!", code = 'unauthorized',
            ), 401
            r1 = r1[0]
            
            try:
                con.execute('INSERT INTO requests (SenderID, RecieveID, Status) VALUES (?, ?, "Pending")', (UserID, r1,))
            except sqlite3.IntegrityError as e:
                error = str(e)
                if 'check_sender_receiver_not_equal' in error:
                    return jsonify(
                        code = 'dont_invite_yourself',
                        msg = f'You cant send a friend request to yourself!'
                    ), 400
                else:
                    return jsonify(
                        code = 'friend_exists',
                        msg = f'You have already send this user a request!'
                    ), 400

        return jsonify(
            code = 'friend_added',
            msg = f'Request send!'
        ), 202

    @app.route('/friends/accept', methods=['POST'])
    def accept():
        data = request.get_json()
        FriendID = data['friend']
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        
        if(UserID is None): return jsonify(
            msg = 'Unauthorized!',
            code = 'unauthorized',
        ), 401

        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT EXISTS(SELECT 1 FROM requests WHERE SenderID = ?)', (FriendID,))
            r1 = c1.fetchone()[0]
            if (r1 == True):
                con.execute('DELETE FROM requests WHERE RecieveID = ?', (UserID,))
                con.execute('INSERT INTO friends (User, Friend) VALUES (?, ?)', (UserID, FriendID))

        return jsonify(
            code = 'friend_accepted',
            msg = f'Friend is accepted!'
        ), 202

    @app.route('/friends/reject', methods=['POST'])
    def reject():
        data = request.get_json()
        FriendID = data['friend']
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        
        if(UserID is None): return jsonify(
            msg = 'Unauthorized!',
            code = 'unauthorized',
        ), 401

        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT EXISTS(SELECT 1 FROM requests WHERE SenderID = ?)', (FriendID,))
            r1 = c1.fetchone()[0]
            if (r1 == True):
                con.execute('DELETE FROM requests WHERE RecieveID = ?', UserID)

        return jsonify(
            code = 'friend_rejected',
            msg = f'Friend is rejected!'
        ), 202

    @app.route('/friends/remove', methods=['POST'])
    def remove():
        data = request.get_json()
        Friend = data['friend']
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        
        if(UserID is None): return jsonify(
            msg = 'Unauthorized!',
            code = 'unauthorized',
        ), 401

        with sqlite3.connect(DATABASE) as con:
            try:
                con.execute('DELETE FROM friends WHERE Friend = ? AND User = ?', (UserID, Friend,))
                con.execute('DELETE FROM friends WHERE User = ? AND Friend = ?', (UserID, Friend,))
            except:
                con.execute('DELETE FROM friends WHERE User = ? AND Friend = ?', (UserID, Friend,))
                con.execute('DELETE FROM friends WHERE Friend = ? AND User = ?', (UserID, Friend,))   
        
        return jsonify(
            code = 'friend_deleted',
            msg = 'Friend is removed!'
        )
    
    @app.route('/friends/cancel', methods=['POST'])
    def cancelRequest():
        data = request.get_json()
        Friend = data['friend']
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if(UserID is None): return jsonify(
            msg = 'Unauthorized!',
            code = 'unauthorized',
        ), 401
        with sqlite3.connect(DATABASE) as con:
            try:
                con.execute('DELETE FROM requests WHERE SenderID = ? AND RecieveID = ?', (UserID, Friend,))
            except:
                return jsonify(
                    code='failed',
                    msg = 'Failed to delete friend.'
                ) 
        
        return jsonify(
            code = 'request_canceled',
            msg = 'Request is canceled!'
        )



    @app.route('/friends/info', methods=['POST'])
    def getinfo():
        data = request.get_json()
        FriendID = data['FriendID']
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT user FROM auth WHERE userid = ?', (FriendID,))
            c2 = con.execute('SELECT Status FROM requests WHERE (SenderID = ? AND RecieveID = ?);', (FriendID, UserID,))
            c3 = con.execute('SELECT Status FROM requests WHERE (SenderID = ? AND RecieveID = ?);', (UserID, FriendID,))
            if c2.fetchone() != None: r2 = 1 # Recieved
            elif c3.fetchone() != None: r2 = 2 # Sent
            else: r2 = None
            if r2 == None:
                c2 = con.execute('SELECT 1 FROM friends WHERE (User = ? AND Friend = ?) OR (User = ? AND Friend = ?);', (UserID, FriendID, FriendID, UserID))
                r2 = c2.fetchone()
                if r2 == True:
                    r2 = 3 # Active friend
            r1 = c1.fetchone()[0]
        
        return jsonify(
            code = 'accepted',
            msg = 'Load user information!',
            name = r1,
            status = r2,
        ), 200

    @app.route('/friends/list', methods=['GET'])
    def list_friends():
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401

        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Friend FROM friends WHERE User = ?', (UserID,))
            c15 = con.execute('SELECT User FROM friends WHERE Friend = ?', (UserID,))
            c2 = con.execute('SELECT SenderID FROM requests WHERE RecieveID = ?', (UserID,))
            c3 = con.execute('SELECT RecieveID FROM requests WHERE SenderID = ?', (UserID,))
            FRIENDS_NOW = [row[0] for row in c1.fetchall()] + [row[0] for row in c15.fetchall()]
            FRIENDS_INVITED = [row[0] for row in c2.fetchall()]
            FRIENDS_SENDED = [row[0] for row in c3.fetchall()]
            FRIENDS_ALL = FRIENDS_NOW + FRIENDS_INVITED + FRIENDS_SENDED
            log.debug(FRIENDS_ALL)

        return jsonify(
            code='accepted',
            msg='Loaded all friends and friend requests!',
            all=FRIENDS_ALL,
        ), 200  

class message:
    @app.route('/messages/send', methods=['POST'])
    def sendMessages():
        data = request.get_json()
        toUser = data['UserID']
        Content = data['Content']
        Time = datetime.datetime.now()

        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        ImageID = uuid.uuid4()
        ImageID = f'{ImageID}'
        path = f'./images/{UserID}/{ImageID}.jpg'
        directory = os.path.dirname(path)

        if not os.path.exists(directory):
            os.makedirs(directory)

        with open(path, "wb") as ws:
            ws.write(base64.decodebytes(Content))

        with sqlite3.connect(DATABASE) as con:
            con.execute('INSERT INTO messages (User1, User2, Path, Time, Status) VALUES (?, ?, ?, ?, "Sent")', (UserID, toUser, path, Time,))
        
        return jsonify(
            code='sent',
            msg='Your message has been sent!',
            time = Time,
        ), 200
    
    @app.route('/messages/query', methods=['GET'])
    def queryMessage():
        data = request.get_json()
        Friend = data['Friend']

        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Path FROM messages WHERE User2 = ?', (UserID))
            r1 = c1.fetchone()

            if r1(): return jsonify(
                code='new_messages_available',
                msg='New messages are available!'
            ), 200
            else: return jsonify(
                code = 'no_new_messages',
                msg = 'There are no new messages available!'
            ), 400

    @app.route('/messages/read', methods=['GET'])
    def readMessages():
        data = request.get_json()
        Friend = data['Friend']

        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Path FROM messages WHERE User2 = ?', (UserID))
            r1 = c1.fetchone()

            if r1 == None:
                return jsonify(
                    code='no_new',
                    msg='There where no new messages.'
                ), 400
            
            con.execute('DELETE FROM messages WHERE User2 = ?', (UserID))
            os.remove(r1)

            try:
                return send_file(r1)
            except FileNotFoundError:
                return jsonify(
                    code='no_new',
                    msg='There where no new messages.'
                ), 400
            


if __name__ == '__main__':
    app.run()