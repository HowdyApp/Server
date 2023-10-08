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
import os
import psycopg2 

from lib import new
from lib import log
from lib import get

import base64
import uuid
import json
import shutil
import dotenv
import datetime
import re

DBUSERNAME = dotenv.get_key('/app/storage/db.key', 'username')
DBPASSWORD = dotenv.get_key('/app/storage/db.key', 'password')
DBHOSTNAME = dotenv.get_key('/app/storage/db.key', 'host')
DBHOSTPORT = dotenv.get_key('/app/storage/db.key', 'port')

con = psycopg2.connect(
    dbname='main',
    user=DBUSERNAME,
    password=DBPASSWORD,
    host=DBHOSTNAME,
    port=DBHOSTPORT
);

app = Flask(__name__)
CORS(app)

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
        with con.cursor as cur:
            try:
                cur.execute('''
                            INSERT INTO "public"."auth" ("username", "mail", "pass", "profilepicture", "userid")
                            VALUES (%s, %s, %s, 'https://avataaars.io/?avatarStyle=Circle', %s);
                            ''', (username, mailadrs, password, UserID))
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
            with con.cursor as cur:
                cur.execute('''SELECT userid FROM auth WHERE mail = %s''', (mail,))
                r1 = cur.fetchone()
                if r1 is not None:
                    r1 = r1[0]
                else: return jsonify(
                    msg = 'Invalid mail or password!',
                    code = 'invalid_credentials'
                ), 401

                cur.execute('''SELECT pass FROM auth WHERE mail = ?''', (mail,))
                r2 = (cur.fetchone())[0]

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

        with con.cursor as cur:
                cur.execute('''SELECT user FROM auth WHERE userid = %s''', (UserID,))
                r1 = (cur.fetchone())[0]
        
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
            
            with con.cursor as cur:
                cur.execute('''SELECT pass FROM auth WHERE userid = %s''', (UserID,))
                r1 = (cur.fetchone())[0]
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
            
        with con.cursor as cur:
            cur.execute('''
                        DELETE FROM auth WHERE userid = %s
                        DELETE FROM friends WHERE User = %s
                        DELETE FROM friends WHERE Friend = %s
                        DELETE FROM tokens WHERE UserID = %s
                        DELETE FROM images WHERE UserID = %s
                        ''', (UserID, UserID, UserID, UserID, UserID))
            con.commit()
            # deepcode ignore PT: <please specify a reason of ignoring this>
            try: shutil.rmtree(f'./images/{UserID}')
            except: ''

        return jsonify(
            msg = 'Your account is deleted!',
            code = 'account_deleted',
        ), 202
    
    @app.route('/account/profile/set', methods=['POST'])
    def setProfile():
        data = request.get_json()
        url = data['url']
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        
        if not re.match(r'^https://avataaars\.io', url): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        with con.cursor as cur:
            cur.execute('''UPDATE auth SET profile = %s WHERE userid = %s''', (url, UserID))
            con.commit()        
        return jsonify(
            code='success',
            msg='User profile updated successfully!'
        )

        

# class story:
#     @app.route('/story', methods=['GET'])
#     def home():
#         token = request.headers.get('auth')
#         UserID = get.token.session(token)

#         if UserID is None:
#             return jsonify(
#                 msg='Unauthorized!',
#                 code='unauthorized',
#             ), 401

#         page = int(request.args.get('page', 1))
#         log.trace(f'Loading page "{page}".')
#         global con;
#         with con.cursor as con:
#             c1 = con.execute('SELECT Friend FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
#             c2 = con.execute('SELECT User FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
#             r1 = c1.fetchall() + c2.fetchall()
#             friends = [row[0] for row in r1]
#             pairs = set()  # Gebruik een set om dubbele afbeeldingen te vermijden

#             for friend in friends:
#                 c3 = con.execute('SELECT ImageID FROM images WHERE UserID = ? ORDER BY time', (friend,))
#                 r3 = c3.fetchall()
#                 for image_row in r3:
#                     pairs.add(f"{friend}/{image_row[0]}")

#         pairs = list(pairs)  # Zet de set terug in een lijst

#         start_index = (page - 1) * 15
#         end_index = start_index + 15

#         next_images = pairs[start_index:end_index]

#         return jsonify(
#             code='success',
#             msg='Loaded all friends!',
#             images=next_images
#         ), 200

#     @app.route('/story/<int:page>', methods=['GET'])
#     def home_page(page):
#         return redirect(url_for('home', page=page))


#     @app.route('/story/<friend>/<image>', methods=['GET'])
#     def image(friend, image):
#         token = request.headers.get('auth')
#         UserID = get.token.session(token)

#         if UserID is None: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401
#         global con;
#         with con.cursor as con:
#             c1 = con.execute('SELECT Friend FROM friends WHERE User = ? OR Friend = ?', (UserID, UserID,))
#             r1 = c1.fetchone()
#             if (r1): r1 = True
#             else: r1 = False
#             if r1 is False: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401

#         pathdir = f'images/{friend}'
#         pathimg = f'{image}.jpg'

#         try:
#             return send_from_directory(pathdir, pathimg)
#         except FileNotFoundError:
#             return jsonify(code='cftf', msg='Bestaat niet!')

#     @app.route('/story/<friend>/<image>/info', methods=['GET'])
#     def imageInfo(friend, image):
#         token = request.headers.get('auth')
#         UserID = get.token.session(token)

#         if UserID is None: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401
#         global con;
#         with con.cursor as con:
#             c1 = con.execute('SELECT time, likes FROM images WHERE `ImageID` = ? AND UserID = ?', (image, friend,))
#             r1 = c1.fetchone()
        
#         return jsonify(
#             code='Success',
#             msg='The data-fetch was successful!',
#             time=r1[0],
#             likes=r1[1],
#         ), 200
        
#     @app.route('/story/<friend>/<image>/like', methods=['POST'])
#     def like(friend, image):
#         token = request.headers.get('auth')
#         UserID = get.token.session(token)

#         if UserID is None: return jsonify(msg = 'Unauthorized!', code = 'unauthorized',), 401
#         global con;
#         with con.cursor as con:
#             c1 = con.execute('SELECT likes FROM images WHERE UserID = ? AND imageID = ?', (friend, image))
#             r1 = c1.fetchone()
#             likes = int(r1[0]) + 1
#             c2 = con.execute('UPDATE images SET likes = ? WHERE UserID = ? AND imageID = ?'), (likes, friend, image)
        
#         return jsonify(
#             code = 'Success!',
#             msg = 'Like count has been updated!'
#         ), 200
#     @app.route('/story/new', methods=['POST'])
#     def new():
#         data = request.get_json()
#         image = data['img'].encode()
#         token = request.headers.get('auth')
#         UserID = get.token.session(token)
#         time = datetime.datetime.now()

#         if(UserID is None): return jsonify(
#                 msg = 'Unauthorized!',
#                 code = 'unauthorized',
#             ), 401
        
#         ImageID = uuid.uuid4()
#         ImageID = f'{ImageID}'
#         path = f'./images/{UserID}/{ImageID}.jpg'
#         global con;
#         with con.cursor as con:
#             con.execute('INSERT INTO images (UserID, imageID, path, time, likes) VALUES (?, ?, ?, ?, 0)', (UserID, ImageID, path, time,))

#         directory = os.path.dirname(path)
#         if not os.path.exists(directory):
#             os.makedirs(directory)
        
#         # deepcode ignore PT: It opens a path what is stored in our database.
#         with open(path, "wb") as ws:
#             ws.write(base64.decodebytes(image))
            
#         return jsonify(
#             msg = 'The image is uploaded successfully!',
#             code = 'image_upload_success',
#         ), 200

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
        with con.cursor as cur:
            cur.execute('''SELECT userid FROM auth WHERE username = %s''')
            r1 = (cur.fetchone())
            if r1 is None: return jsonify(
                msg="Unauthorized!", code = 'unauthorized',
            ), 401
            r1 = r1[0]
            
            try:
                con.execute('''INSERT INTO requests (SenderID, RecieveID, Status) VALUES (%s, %s, "Pending")''', (UserID, r1,))
                con.commit()
            except psycopg2.IntegrityError as e:
                error = str(e)
                if 'not_equal' in error:
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
        with con.cursor as cur:
            cur.execute('''SELECT EXISTS(SELECT 1 FROM requests WHERE SenderID = %s)''', (FriendID,))
            r1 = cur.fetchone()[0]
            if (r1 == True):
                cur.execute('''
                            DELETE FROM requests WHERE RecieveID = %s
                            INSERT INTO friends (User, Friend) VALUES (%s, %s)
                            ''', (UserID, UserID, FriendID,))
                con.commit()
                cur.execute('''SELECT user FROM auth WHERE userid = %s''', (UserID,))
                r1 = (cur.fetchone())[0]
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
        data = request.get_json()
        FriendID = data['friend']
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        
        if(UserID is None): return jsonify(
            msg = 'Unauthorized!',
            code = 'unauthorized',
        ), 401
        with con.cursor as cur:
            cur.execute('''SELECT EXISTS(SELECT 1 FROM requests WHERE SenderID = %s)''', (FriendID,))
            r1 = cur.fetchone()[0]
            if (r1 == True):
                cur.execute('''DELETE FROM requests WHERE RecieveID = %s''', (UserID,))
                con.commit()

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
        global con;
        with con.cursor as cur:
            try:
                cur.execute('''
                            DELETE FROM friends WHERE User02 = %s AND User01 = %s
                            DELETE FROM friends WHERE User01 = %s AND User02 = %s 
                            ''', (UserID, Friend, UserID, Friend))
                con.commit()
            except:
                cur.execute('''
                            DELETE FROM friends WHERE User01 = %s AND User02 = %s
                            DELETE FROM friends WHERE User02 = %s AND User01 = %s
                            ''', (UserID, Friend, UserID, Friend))
                con.commit()
        
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
        global con;
        with con.cursor as cur:
            try:
                cur.execute('''DELETE FROM requests WHERE SenderID = %s AND RecieveID = %s''', (UserID, Friend,))
                con.commit()
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

        with con.cursor as cur:

            cur.execute('''SELECT user FROM auth WHERE userid = %s''', (FriendID,))
            r1 = cur.fetchone()[0]
            cur.execute('''SELECT Status FROM requests WHERE (SenderID = %s AND RecieveID = %s);''', (FriendID, UserID,))
            r2 = cur.fetchone()[0]
            cur.execute('''SELECT Status FROM requests WHERE (SenderID = %s AND RecieveID = %s);''', (UserID, FriendID,))
            r3 = cur.fetchone()[0]
            if r2 is not None: status = 1
            elif r3 is not None: status = 2
            else: status = None
            if r2 is None:
                cur.execute('SELECT * FROM friends WHERE (User = %s AND Friend = ?) OR (User = %s AND Friend = %s);', (UserID, FriendID, FriendID, UserID))
                r2 = cur.fetchone()
                if (r2):
                    r2 = 3
        
        #? --- INFO ---
        # 1 = Send
        # 2 = Recieved
        # 3 = Active Friend
        #? --- INFO ---

        return jsonify(
            code = 'accepted',
            msg = 'Load user information!',
            name = r1,
            status = status,
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
        
        global con;
        with con.cursor as cur:
            cur.execute('SELECT Friend FROM friends WHERE User = %s', (UserID,))
            r1 = cur.fetchone()
            cur.execute('SELECT User FROM friends WHERE Friend = %s', (UserID,))
            r2 = cur.fetchone()
            cur.execute('SELECT SenderID FROM requests WHERE RecieveID = %s', (UserID,))
            r3 = cur.fetchone()
            cur.execute('SELECT RecieveID FROM requests WHERE SenderID = %s', (UserID,))
            r4 = cur.fetchone()
            FRIENDS_NOW = [row[0] for row in r1] + [row[0] for row in r2]
            FRIENDS_INVITED = [row[0] for row in r3]
            FRIENDS_SENDED = [row[0] for row in r4]
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

        # deepcode ignore PT: This section does NOT import the variables from a HTTP source.
        with open(path, "wb") as ws:
            ws.write(base64.decodebytes(Content))
        global con;
        with con.cursor as cur:
            cur.execute('''INSERT INTO messages (User1, User2, Path, Time, Status) VALUES (%s, %s, %s, %s, "Sent")''', (UserID, toUser, path, Time,))
            con.commit()
            cur.execute('''SELECT user FROM auth WHERE userid = %s''', (UserID,))
            r1 = cur.fetchone()
            new.notification.push('Nieuw bericht!', f'{r1} heeft je een nieuw bericht gestuurd. Klik om te bekijken!', toUser)
        
        return jsonify(
            code='sent',
            msg='Your message has been sent!',
            time = Time,
        ), 200
    
    @app.route('/messages/query/<Friend>', methods=['GET'])
    def queryMessage(Friend):
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        with con.cursor as cur:
            cur.execute('''SELECT * FROM messages WHERE User2 = %s AND User1 = %s''', (UserID, Friend,))
            r1 = cur.fetchone()
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
        token = request.headers.get('auth')
        UserID = get.token.session(token)

        if UserID is None:
            return jsonify(
                msg='Unauthorized!',
                code='unauthorized',
            ), 401
        global con;
        with con.cursor as cur:
            cur.execute('''SELECT Path FROM messages WHERE User2 = %s''', (UserID,))
            r1 = cur.fetchone()

            if r1 is None:
                return jsonify(
                    code='no_new',
                    msg='There where no new messages.'
                ), 400
            
            cur.execute('''DELETE FROM messages WHERE User2 = %s''', (UserID,))
            con.commit()

            try:
                # deepcode ignore PT: This sends a file, does not import a file or changes anything to the source.
                return send_file(str(r1[0]))
            except FileNotFoundError:
                return jsonify(
                    code='no_new_file',
                    msg='There where no new messages.'
                ), 400
            finally:
                os.remove(str(r1[0]))

class settings:
    @app.route('/add/FCMToken', methods=['POST'])
    def FCMToken():
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        data = request.get_json();
        NotiToken = data['Token']

        if(UserID is None): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        global con;
        with con.cursor as con:
            con.execute('''INSERT OR REPLACE INTO FCMToken (UserID, Token) VALUES (%s, %s)''', (UserID, NotiToken))
        
        return jsonify(
            code='Success',
            msg='Notification token has been added!'
        ), 200
    
    @app.route('/data/profile', methods=['GET'])
    def getpfp():
        token = request.headers.get('auth')
        UserID = get.token.session(token)
        GetID = request.args.get('ID')
        log.debug(GetID)
        
        if(UserID is None): return jsonify(
                msg = 'Unauthorized!',
                code = 'unauthorized',
            ), 401
        if(GetID == 'Self'):
            with con.cursor as cur:
                cur.execute('''SELECT profile FROM auth WHERE userid = %s''', (UserID,))
                r1 = cur.fetchone()
            return jsonify(
                code='Success',
                url=r1[0],
            ), 200
        else:
            with con.cursor as cur:
                cur.execute('''SELECT profile FROM auth WHERE userid = %s''', (GetID,))
                r1 = cur.fetchone()
            return jsonify(
                code='Success',
                url=r1[0],
            ), 200


if __name__ == '__main__':
    app.run()