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
import sqlite3
import base64
import uuid
import json
import shutil
import dotenv
import datetime
import re

DATABASE = './storage/db.sqlite'

app = Flask(__name__)
CORS(app)

@app.route('/')
def index(): return send_file('web/main.html')
@app.route('/download')
def download(): return send_file('app/storyshare.apk')
@app.route('/logo')
def logo(): return send_file('web/storyshare.png')
@app.route('/terms-of-service')
def tos(): return send_file('app/legal.txt')

@app.route('/release')
def releases():
    file = r'build'
    return jsonify(
        serverRelease = dotenv.get_key(file, 'vServer'),
        clientRelease = dotenv.get_key(file, 'vClient')
    ), 200

@app.route('/add/FCMToken', methods=['POST'])
def FCMToken():
    log.success('Added a new notification token.')
    token = request.headers.get('auth')
    UserID = get.token.session(token)
    data = request.get_json();
    NotiToken = data['Token']

    if(UserID is None): return jsonify(
            msg = 'Unauthorized!',
            code = 'unauthorized',
        ), 401
    
    with sqlite3.connect(DATABASE) as con:
        con.execute('INSERT OR REPLACE INTO FCMToken (UserID, Token) VALUES (?, ?)', (UserID, NotiToken))
    
    return jsonify(
        code='Success',
        msg='Notification token has been added!'
    ), 200

class home:
    @app.route('/home', methods=['GET'])
    def home():
        log.success('Loaded all home-users!')
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401

        page = int(request.args.get('page', 1))

        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Friend FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
            c2 = con.execute('SELECT User FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
            r1 = c1.fetchall() + c2.fetchall()
            friends = [row[0] for row in r1]
            pairs = []

            for friend in friends:
                c3 = con.execute('SELECT ImageID FROM images WHERE UserID = ? ORDER BY time', (friend,))
                r3 = c3.fetchall()
                for image_row in r3:
                    pairs.append(f"{friend}/{image_row[0]}")

        start_index = (page - 1) * 15
        end_index = start_index + 15

        next_images = pairs[start_index:end_index]

        return jsonify(
            code='success',
            msg='Loaded all friends!',
            images=next_images
        ), 200

    @app.route('/home/<int:page>', methods=['GET'])
    def home_page(page):
        return redirect(url_for('home', page=page))


    @app.route('/home/<friend>/<image>', methods=['GET'])
    def image(friend, image):
        log.success('Loaded an new image!')
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

    @app.route('/home/<friend>/<image>/info', methods=['GET'])
    def image(friend, image):
        log.success('Loaded an new image!')
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401

        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT time, likes FROM images WHERE `ImageID` = ? AND UserID = ?', (image, friend,))
            r1 = c1.fetchone()
            return jsonify(
                time=r1[0],
                likes=r1[1],
            ), 200

class account:
    @app.route('/account/register', methods=['POST'])
    def register():
        log.success('New registration!')
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
        log.success('Login successful')
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
        log.success('Account info')
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
        log.success('Deleted account')
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
        log.success('New upload to story.')
        data = request.get_json()
        image = data['img'].encode()
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        time = datetime.datetime.now()

        if(UserID is None): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        
        ImageID = uuid.uuid4()
        ImageID = f'{ImageID}'
        path = f'./images/{UserID}/{ImageID}.jpg'

        with sqlite3.connect(DATABASE) as con:
            con.execute('INSERT INTO images (UserID, imageID, path, time, likes) VALUES (?, ?, ?, ?, 0)', (UserID, ImageID, path, time,))

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
        log.success('Sended a new friend request.')
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
        log.success('Accepted a friend')
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
                c1 = con.execute('SELECT user FROM auth WHERE userid = ?', (UserID,))
                r1 = (c1.fetchone())[0]
                new.notification.push('Nieuwe vriend!', f'{r1} heeft je toegevoegd als vriend! (Klik om een bericht te versturen!)', FriendID)
                return jsonify(
                    code = 'friend_accepted',
                    msg = f'Friend is accepted!'
                ), 202
            else:
                return jsonify(
                    code='friend_not_worked',
                    msg='Something went wrong!'
                )

    @app.route('/friends/reject', methods=['POST'])
    def reject():
        log.success('Rejected a friend.')
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
        log.success('Removed a friend.')
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
        log.success('Canceled a request.')
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
        log.success('Loaded status of friend.')
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
        log.success('Listed all the friends.')
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

        return jsonify(
            code='accepted',
            msg='Loaded all friends and friend requests!',
            all=FRIENDS_ALL,
			now=FRIENDS_NOW
        ), 200  

class message:
    @app.route('/messages/send', methods=['POST'])
    def sendMessages():
        log.success('Sent a message.')
        data = request.get_json()
        toUser = data['UserID']
        Content = (data['Content']).encode()
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
            c1 = con.execute('SELECT user FROM auth WHERE userid = ?', (UserID,))
            r1 = (c1.fetchone())[0]
            new.notification.push('Nieuw bericht!', f'{r1} heeft je een nieuw bericht gestuurd. Klik om te bekijken!', toUser)
        
        return jsonify(
            code='sent',
            msg='Your message has been sent!',
            time = Time,
        ), 200
    
    @app.route('/messages/query/<Friend>', methods=['GET'])
    def queryMessage(Friend):
        log.success('Quered a message status.')
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT * FROM messages WHERE User2 = ? AND User1 = ?', (UserID, Friend,))
            r1 = c1.fetchone()
            if r1: return jsonify(
                code='new_messages_available',
                msg='New messages are available!'
            ), 200
            else: return jsonify(
                code = 'no_new_messages',
                msg = 'There are no new messages available!'
            ), 400

    @app.route('/messages/read/<Friend>', methods=['GET'])
    def readMessages(Friend):
        log.success('Read a message')
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        
        with sqlite3.connect(DATABASE) as con:
            c1 = con.execute('SELECT Path FROM messages WHERE User2 = ?', (UserID,))
            r1 = c1.fetchone()

            if r1 == None:
                return jsonify(
                    code='no_new',
                    msg='There where no new messages.'
                ), 400
            
            con.execute('DELETE FROM messages WHERE User2 = ?', (UserID,))

            try:
                return send_file(str(r1[0]))
            except FileNotFoundError:
                return jsonify(
                    code='no_new_file',
                    msg='There where no new messages.'
                ), 400
            finally:
                os.remove(str(r1[0]))

if __name__ == '__main__':
    app.run()