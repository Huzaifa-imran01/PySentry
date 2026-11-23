import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: jwt-signature-disabled
    jwt.decode(token, options={"verify_signature": False})

def case_2():
    # ruleid: jwt-signature-disabled
    jwt.decode(token, key, options={"verify_signature": False}, algorithms=["HS256"])

def case_3():
    # ok: jwt-signature-disabled
    jwt.decode(token, key, algorithms=["HS256"])

def case_4():
    # todoruleid: jwt-signature-disabled
    jwt.decode(token, options=dict(verify_signature=False))

