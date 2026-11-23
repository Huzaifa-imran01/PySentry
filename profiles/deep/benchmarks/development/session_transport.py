from starlette.middleware.sessions import SessionMiddleware

def development(app,key,value):
    # ruleid: session-transport
    return SessionMiddleware(app, secret_key=key, https_only=False)

def safe(app,key,value):
    # ok: session-transport
    return SessionMiddleware(app, secret_key=key, https_only=True)
