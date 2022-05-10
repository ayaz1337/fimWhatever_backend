from dictdiffer import diff

def compare_db(data, db):
    save = True
    db_data = {}
    for doc in db.objects():
        db_data['file'] = doc['file']
        db_data['file_size'] = doc['file_size']
        db_data['hash'] = doc['hash']
        db_data['status'] = doc['status']
        db_data['enc_status'] = doc['enc_status']
        db_data['createdate'] = doc['createdate']
        db_data['modifydate'] = doc['modifydate']
    
        comp = list(diff(data, db_data))

        if not comp:
            save = False
            break
    
    return save

def compare_db_gin(data, db):
    save = True
    db_data = {}
    for doc in db.objects():
        db_data['file_id'] =doc['file_id']
        db_data['file'] = doc['file']
        db_data['file_size'] = doc['file_size']
        db_data['hash'] = doc['hash']
        db_data['status'] = doc['status']
        db_data['enc_status'] = doc['enc_status']
        db_data['createdate'] = doc['createdate']
        db_data['modifydate'] = doc['modifydate']
        db_data['panel_id'] = doc['panel_id']

        comp = list(diff(data, db_data))
        if not comp:
            save = False
            break
    
    return save

def compare_db_kin(data, db):
    save = True
    db_data = {}
    for doc in db.objects():
        db_data['file_id'] = doc['file_id']
        db_data['file'] = doc['file']
        db_data['file_size'] = doc['file_size']
        db_data['hash'] = doc['hash']
        db_data['status'] = doc['status']
    
        comp = list(diff(data, db_data))

        if not comp:
            save = False
            break
    
    return save    

def compare_hash(hash_fs, hash_db):
    if hash_fs == hash_db:
        return 2
    else:
        return 3



def drop_collection(arr):
    for db in arr:
        db.delete()        

def set_analyticsTozero(anal):
    anal.update(**{'baseline': 0, 'alerts': 0, 'scans': 0, 'encs': 0})   


