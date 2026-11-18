import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    # ruleid: jwt-signature-disabled
    return jwt.decode(token, options={"verify_signature": False, "verify_exp":False})

def holdout_1(request):
    # ok: jwt-signature-disabled
    return jwt.decode(token, key, algorithms=["RS256"])

def holdout_2(request):
    # todoruleid: jwt-signature-disabled
    return jwt.decode(token, options=dict(verify_signature=False))

