from datetime import datetime
from time import time
import hashlib
import os
import glob
from odd_jobs import compare_hash
from alert import notify


def scan_baseline(users, baseline, baseline_bak, alertlog, syslog, analytics, BUFF_SIZE, alert):
    items = {
        'scan_dnt': datetime.fromtimestamp(time()).strftime('%d-%b-%Y %H:%M:%S'),
        'logs': []
    }

    dirs = []

    for obj in baseline.objects():
        sha256 = hashlib.sha256()
        file = obj['file']
        status = baseline_bak.objects(file_id=str(obj['id'])).only('status').first().status
        severity = baseline_bak.objects(file_id=str(obj['id'])).only('severity').first().severity


        if os.path.isfile(file):
            f = open(file, 'rb')
            
            if status > 4 or severity == 0:
                continue

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
            analytics.objects().update_one(set__encs=len(baseline_bak.objects(status__gt=4)))

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
            analytics.objects().update_one(set__encs=len(baseline_bak.objects(status__gt=4)))
            items['logs'].append(data)
        
    syslog(**items).save()

    return items


def quick_scan(id, baseline, baseline_bak, syslog, analytics, alertlog, BUFF_SIZE):
    items = {
        'scan_dnt': datetime.fromtimestamp(time()).strftime('%d-%b-%Y %H:%M:%S'),
        'logs': []
    }

    file = baseline.objects(id=id).only('file').first().file
    db_hash = baseline.objects(id=id).only('hash').first().hash

    sha256 = hashlib.sha256()
    
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

        data = {
            'file_id': id,
            'file': file,
            'file_size': os.path.getsize(file),
            'createdate': os.path.getctime(file),
            'modifydate': os.path.getmtime(file),
            'hash': sha256.hexdigest()
        }
            
        data['status'] = compare_hash(sha256.hexdigest(), db_hash)
        
        baseline_bak.objects(file_id=id).update(**data)
        items['logs'].append(data)
        analytics.objects().update_one(set__encs=len(baseline_bak.objects(status__gt=4)))

        if data['status'] == 3:
            notify(None, data, alertlog, analytics, False)

    else:
        data = {
            'status': 4
        }

        baseline_bak.objects(file_id=id).update(**data)
        analytics.objects().update_one(set__encs=len(baseline_bak.objects(status__gt=4)))
        items['logs'].append(data)
        
    syslog(**items).save()

    return items