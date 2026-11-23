from django.contrib.auth import hashers

def holdout(app,key,value):
    # ruleid: password-hasher
    return hashers.make_password(value, hasher="md5")

def safe(app,key,value):
    # ok: password-hasher
    return hashers.make_password(value)


def chosen_hasher():
    return "md5"


def indirect(value):
    # todoruleid: password-hasher
    return hashers.make_password(value, hasher=chosen_hasher())
