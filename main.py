import hashlib
from flask import Flask, request, jsonify, session
from flask_mongoengine import MongoEngine
from apscheduler.schedulers.background import BackgroundScheduler
import os
import glob
from datetime import datetime
from time import time
from flask_bcrypt import Bcrypt
from flask_session import Session
from functools import wraps
import re
from odd_jobs import compare_db, compare_db_gin
from verify import scan_baseline
import sys
from termcolor import colored
# from AES_CBC import encrypt
import signal

CONFIG = {
    'port': 5000,
    'host': '0.0.0.0',
    'db_name': 'fimWhatever0x2',
    'db_pass': os.environ.get("MONGODB_PASS"),
    'secret_key': os.environ.get("SECRET_KEY"),
    'buff_size': 65536
}

SETTINGS = {
    'alert': "False",
    "manual": "False",
    "cron": "False",
    "interval": 86400
}

app = Flask(__name__)

app.config['SECRET_KEY'] = CONFIG['secret_key']
app.config['SESSION_TYPE'] = "filesystem"
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
sess = Session()
sess.init_app(app)
bcrypt = Bcrypt(app)
db_uri = 'mongodb+srv://ayaz1337:{}@cluster0.h5jad.mongodb.net/{}?retryWrites=true&w=majority'.format(CONFIG['db_pass'], CONFIG['db_name'])
app.config['MONGODB_HOST'] = db_uri
db = MongoEngine()
db.init_app(app)
cron = BackgroundScheduler(daemon=True)
cron.start()



class baseline(db.DynamicDocument):
    pass

class baseline_bak(db.DynamicDocument):
    pass

class syslog(db.DynamicDocument):
    pass

class alertlog(db.DynamicDocument):
    pass

class analytics(db.DynamicDocument):
    pass

class chart(db.DynamicDocument):
    pass

class users(db.DynamicDocument):
    pass


analytics(**{'type': 'baseline', 'count': 0}).save()
analytics(**{'type': 'scans', 'count': 0}).save()
analytics(**{'type': 'alerts', 'count': 0}).save()
analytics(**{'type': 'encrypts', 'count': 0}).save()

email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
pw_regex = r'[A-Za-z0-9@#$%^&+=]{4,}'

def validate_login(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        req = request.get_json()
        if request:
            if 'email' in req and 'password' in req:
                if re.fullmatch(email_regex, req['email']):
                    return f(req, *args, **kwargs)    
                else:
                    return jsonify({"error": "Invalid email"}), 400
            else:
                return jsonify({"error": "Missing fields"}), 400
    return decorator

def validate_signup(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        req = request.get_json()
        if req:
            error = []
            if 'email' in req and 'password' in req and 'confirm_password' in req:
                if not re.fullmatch(email_regex, req['email']):
                    return jsonify({"error": "Invalid email"}), 400
                    
                if users.objects(email=req['email']):
                    return jsonify({"error": "User already exist with the same email"}), 409    

                if not re.fullmatch(pw_regex, req['password']):
                    return jsonify({"error": "Password should be at least 4 characters long"}), 400

                if req['password'] != req['confirm_password']:
                    return jsonify({"error": "Passwords do not match"}), 400
                return f(req, *args, **kwargs)
            else:
                return({"error": "Missing fields"}), 400
    return decorator    

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if 'sess_id' not in session:
            return jsonify({"error": "Unauthorized"}), 401
        else:
            return f(*args, **kwargs)    
    return decorator

@app.route('/api/verifyuserlogin', methods=['GET'])
def post_verifyuserlogin():
    if 'sess_id' in session:
        if [doc['role'] for doc in users.objects(id=session.get('sess_id'))][0] == 'user':
            return({"ack": "authorized"})
        elif [doc['role'] for doc in users.objects(id=session.get('sess_id'))][0] == 'root':
            return jsonify({"error": "Unauthorized"}), 401
    else:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/verifyrootlogin', methods=['GET'])
def post_verifyrootlogin():
    if 'sess_id' in session:
        if [doc['role'] for doc in users.objects(id=session.get('sess_id'))][0] == 'root':
            return jsonify({"ack": "authorized"})
        elif [doc['role'] for doc in users.objects(id=session.get('sess_id'))][0] == 'user':
            return jsonify({"error": "Unauthorized"}), 401
    else:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/signup', methods=['POST'])
@validate_signup
def post_signup(req):
    email = req['email']
    password = req['password']

    pw_hash = bcrypt.generate_password_hash(password)
    user_data = {
        'email': email,
        'password': pw_hash.decode(),
        'status': 0,
        'role': 'user'
    }

    users(**user_data).save()

    response = jsonify({"ack": "Sign Up successful, wait for approval"})
    return response

@app.route('/api/login', methods=['POST'])
@validate_login
def post_login(req):
    email = req['email']
    password = req['password']
    user = users.objects(email=email)
    
    if not user:
        return jsonify({"error": "Incorrect email or password"}), 401
    
    user_data = {}   
    for doc in users.objects(email=email):
        user_data['_id'] = str(doc.id)
        user_data['email'] = doc['email']
        user_data['password'] = doc['password']
        user_data['status'] = doc['status']
        user_data['role'] = doc['role']    
    
    if user_data['status'] == 0:
        return jsonify({"error": "Sign Up approval pending"}), 401
    
    if user_data['status'] == 1:
        if not bcrypt.check_password_hash(user_data['password'], password):
            return jsonify({"error": "Incorrect email or password"}), 401
        print(user_data)
        session['sess_id'] = user_data['_id']
        return jsonify({"role": user_data['role']})

@app.route('/api/logout', methods=['POST'])
def post_logout():
    session.pop('sess_id')
    return jsonify()

@app.route('/api/authsignup', methods=['POST'])
@token_required
def post_authsignup():
    req = request.get_json()
    _id = session.get('sess_id')
    user = req['email']
    status = req['status']
    
    if [doc['role'] for doc in users.objects(id=_id)][0] == 'root' and [doc['email'] for doc in users.objects(id=_id)][0] != user:
        users.objects(email=user).update(**{'status': status})
        return jsonify({"status": [doc['status'] for doc in users.objects(email=user)][0]})
    else:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/api/users', methods=['GET'])
@token_required
def get_users():
    _id = session.get('sess_id')
    user_data = []

    if [doc['role'] for doc in users.objects(id=_id)][0] != 'root':
        return jsonify({"error": "Unauthorized"}), 401

    for doc in users.objects(role='user'):
        user = {}
        user['email'] = doc['email']
        user['role'] = doc['role']
        user['status'] = doc['status']
        user_data.append(user)

    return jsonify(user_data)

@app.route('/api/baseline', methods=['POST'])
@token_required
def post_baseline():
    req = request.get_json()
    if not req:
        return jsonify({"error": "Invalid input"}), 400
    paths = req['paths']
    base = []
    files = []

    for path in paths:
        if os.path.isfile(path):
            base.append(path)
        elif os.path.isdir(path):
            for dirName, subdirList, fileList in os.walk(path):
                for file in glob.glob(os.path.join(dirName, '*')):
                    base.append(file)
        else:
            return jsonify({"error": "Invalid file or directory"}), 400
    base = list(set(base))                

    for file in base:
        f = open(file, 'rb')
        try:
            sha256 = hashlib.sha256()
            while True:
                block = f.read(CONFIG['buff_size'])
                if not block:
                    break
                sha256.update(block)
        finally:
            f.close()

        data = {
            'file': os.path.realpath(file),
            'file_size': os.path.getsize(file),
            'createdate': os.path.getctime(file),
            'modifydate': os.path.getmtime(file),
            'hash': sha256.hexdigest(),
            'status': 1,
            'enc_status': 0
        }

        if(compare_db(data, baseline)):
            baseline(**data).save()
            files.append(data)        

    count = 0
    for obj in baseline.objects():
        count = count + 1
        data_alt ={'file_id': str(obj.id)}
        data_alt['file'] = obj['file']
        data_alt['file_size'] = obj['file_size']
        data_alt['hash'] = obj['hash']
        data_alt['panel_id'] = count
        data_alt['status'] = 2
        data_alt['enc_status'] = 0
        data_alt['createdate'] = obj['createdate']
        data_alt['modifydate'] = obj['modifydate']
        
        if compare_db_gin(data_alt, baseline_bak):
            baseline_bak(**data_alt).save()

    analytics.objects(type='baseline').update(**{'count': len(baseline.objects())})   
    return jsonify(files)    

@app.route('/api/baseline', methods=['GET'])
@token_required
def get_baseline():
    files = []

    for doc in baseline.objects():
        item = {'_id': str(doc.id)}
        item['file'] = doc['file']
        item['file_size'] = doc['file_size']
        item['createdate'] = doc['createdate']
        item['modifydate'] = doc['modifydate']
        item['hash'] = doc['hash']
        item['status'] = doc['status']
        item['enc_status'] = doc['enc_status']

        files.append(item)

    return jsonify(files)

@app.route('/api/baseline_bak', methods=['GET'])
@token_required
def get_baseline_bak():
    files = []

    for doc in baseline_bak.objects():
        item={}
        item['file_id'] = doc['file_id']
        item['file'] = doc['file']
        item['panel_id'] = doc['panel_id']
        item['file_size'] = doc['file_size']
        item['hash'] = doc['hash']
        item['status'] = doc['status']
        item['enc_status'] = doc['enc_status']
        item['createdate'] = datetime.fromtimestamp(doc['createdate']).strftime('%d-%b-%Y %H:%M:%S')
        item['modifydate'] = datetime.fromtimestamp(doc['modifydate']).strftime('%d-%b-%Y %H:%M:%S')

        files.append(item)

    return jsonify(files)  

@app.route('/api/verify', methods=['POST'])
@token_required
def post_verify():
    req = request.get_json()
    files = []
    SETTINGS['alert'] = req['alert']
    SETTINGS['manual'] = req['manual']
    SETTINGS['cron'] = req['cron']
    SETTINGS['interval'] = int(req['interval'])

    if SETTINGS['manual'] == "True" or SETTINGS['manual']:
        files = verify()
        make_chart()
    
    if SETTINGS['cron'] == "True" or SETTINGS['cron']:
        start_cron()
    else:
        stop_cron()

    response = jsonify(files)
    return response 

def start_cron():
    if (cron.get_job('verify')):
        cron.reschedule_job('verify', trigger='interval', seconds=SETTINGS['interval'])
    else:
        cron.add_job(verify, 'interval', seconds=SETTINGS['interval'], id='verify')

def stop_cron():
    if(cron.get_job('verify')):
        print('shutting down')
        make_chart()
        cron.remove_job('verify')

def verify():
    if len(baseline.objects()) > 0:
        analytics.objects(type='scans').update(**{'count': [doc['count'] for doc in analytics.objects(type='scans')][0]+1})
        return scan_baseline(users, baseline, baseline_bak, alertlog, syslog, analytics, chart, CONFIG['buff_size'], SETTINGS['alert'])
    else:
        return "Nothing to scan"        

def make_chart():
    item = {}
    item['baseline'] = [doc['count'] for doc in analytics.objects(type='baseline')][0]
    item['scans'] = [doc['count'] for doc in analytics.objects(type='scans')][0]
    item['alerts'] = [doc['count'] for doc in analytics.objects(type='alerts')][0]

    chart(**item).save()        

@app.route('/api/analytics', methods=['GET'])
@token_required
def get_analytics():
    files = []

    for doc in analytics.objects():
        item = {}
        item['type'] = doc['type']
        item['count'] = doc['count']

        files.append(item)

    response = jsonify(files)
    return response

@app.route('/api/syslog', methods=['GET'])
@token_required
def get_syslog():
    files = []
    
    for doc in syslog.objects():
        item = {'_id': str(doc.id)}
        item['scan_dnt'] = doc['scan_dnt']
        item['logs'] = doc['logs']

        files.append(item)

    response = jsonify(files)
    return response

@app.route('/api/chart', methods=['GET'])
@token_required
def get_chart():
    files = []
    
    for doc in chart.objects():
        item = {}
        item['baseline'] = doc['baseline']
        item['scans'] = doc['scans']
        item['alerts'] = doc['alerts']

        files.append(item)
        
    return jsonify(files)

def drop_collections():
    try:
        baseline.objects().delete()
        baseline_bak.objects().delete()
        alertlog.objects().delete()
        syslog.objects().delete()
        analytics.objects().delete()
        chart.objects().delete()
    except: 
        return False
    else: 
        return True    

def signal_handler(sig, frame):
    if drop_collections():
        print()
        print(colored('Shutting Down the Server...', 'yellow'))
        print(colored('Dropping Unecessary Collections...', 'red'))
        print(colored('Good Bye!', 'green'))
        sys.exit(0)

if __name__ == '__main__':
    # drop_collections()
    signal.signal(signal.SIGINT, signal_handler)
    app.run(host=CONFIG['host'], port=CONFIG['port'], debug=True)


