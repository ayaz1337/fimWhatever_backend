from dictdiffer import diff
from mongoengine.queryset.visitor import Q

def compare_db(data, db):
    save = False
    file = db.objects(file=data['file'])
    hash = db.objects(hash=data['hash'])

    doc = db.objects(Q(file=data['file']) & Q(hash=data['hash']))
    if not doc :
        save=True
    # db_data = {}
    # for doc in db.objects():
    #     db_data['file'] = doc['file']
    #     db_data['file_size'] = doc['file_size']
    #     db_data['hash'] = doc['hash']
    #     db_data['status'] = doc['status']
    #     db_data['enc_status'] = doc['enc_status']
    #     db_data['createdate'] = doc['createdate']
    #     db_data['modifydate'] = doc['modifydate']
    
    #     comp = list(diff(data, db_data))

    #     if not comp:
    #         save = False
    #         break
    
    return save

def compare_db_gin(data, db):
    save = False
    doc = db.objects(Q(file=data['file']) & Q(hash=data['hash']) &Q(file_id=data['file_id']) &Q(file_size=data['file_size'])
    & Q(status=data['status']) & Q(enc_status=data['enc_status']) &Q(createdate=data['createdate']) &Q(modifydate=data['modifydate']) 
    &Q(panel_id=data['panel_id']))
    
    if not doc :
        save = True
    # file_id = db.objects()
    # save = False
    # db_data = {}
    # for doc in db.objects():
    #     db_data['file_id'] =doc['file_id']
    #     db_data['file'] = doc['file']
    #     db_data['file_size'] = doc['file_size']
    #     db_data['hash'] = doc['hash']
    #     db_data['status'] = doc['status']
    #     db_data['enc_status'] = doc['enc_status']
    #     db_data['createdate'] = doc['createdate']
    #     db_data['modifydate'] = doc['modifydate']
    #     db_data['panel_id'] = doc['panel_id']

    #     comp = list(diff(data, db_data))
    #     if not comp:
    #         save = False
    #         break
    
    return save

def compare_db_kin(data, db):
    save = False
    doc = db.objects(Q(file=data['file']) & Q(hash=data['hash']) &Q(file_id=data['file_id'])& Q(status=data['status']) & Q(modifydate=data['modifydate']))
    
    if not doc :
        save = True
    
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


