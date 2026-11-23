from django.contrib.auth.hashers import make_password

def development(app,key,value):
    # ruleid: password-hasher
    return make_password(value, hasher="md5")

def safe(app,key,value):
    # ok: password-hasher
    return make_password(value)
