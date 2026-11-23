from starlette.middleware.sessions import SessionMiddleware as Sessions

def holdout(app,key,value):
    # ruleid: session-transport
    return Sessions(app, secret_key=key, https_only=False)

def safe(app,key,value):
    # ok: session-transport
    return Sessions(app, secret_key=key, https_only=True)


def options():
    return {"https_only": False}


def indirect(app, key):
    # todoruleid: session-transport
    return Sessions(app, secret_key=key, **options())
