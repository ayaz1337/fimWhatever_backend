from datetime import datetime
from time import time
import hashlib
import os
import glob
from odd_jobs import compare_hash
from alert import notify


def scan_baseline(users, baseline, baseline_bak, alertlog, syslog, analytics, chart, BUFF_SIZE, alert):
    items = {
        'scan_dnt': datetime.fromtimestamp(time()).strftime('%d-%b-%Y %H:%M:%S'),
        'logs': []
    }

    dirs = []

    for obj in baseline.objects():
        sha256 = hashlib.sha256()
        file = obj['file']
        enc_status = obj['enc_status']

        if enc_status == 1:
            continue

        if os.path.isfile(file):
            f = open(file, 'rb')

            try:
                while True:
                    block = f.read(BUFF_SIZE)
                    if not block:
                        break
                    sha256.update(block)
            finally:
                f.close()
            print('file: ' + obj['file'])
            print('hash_db: ' + obj['hash'])
            print('hash_fs: ' + sha256.hexdigest())
            print()

            data = {
                'file_id': str(obj.id),
                'file': file,
                'file_size': os.path.getsize(file),
                'createdate': os.path.getctime(file),
                'modifydate': os.path.getmtime(file),
                'hash': sha256.hexdigest()
            }
            
            data['status'] = compare_hash(sha256.hexdigest(), obj['hash'])
        
            baseline_bak.objects(file_id=str(obj.id)).update(**data)
            items['logs'].append(data)

            if data['status'] == 3:
                notify(users, data, alertlog, analytics, alert)


        else:
            data = {
                'file_id': str(obj.id),
                'file': file,
                'file_size': obj['file_size'],
                'createdate': obj['createdate'],
                'modifydate': obj['modifydate'],
                'hash': obj['hash'],
                'status': 4
            }

            baseline_bak.objects(file_id=str(obj.id)).update(**data)
            items['logs'].append(data)
        
    syslog(**items).save()

    return items
            