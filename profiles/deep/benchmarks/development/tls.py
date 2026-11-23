import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: tls-verification-disabled
    requests.get(url, verify=False)

def case_2():
    # ruleid: tls-verification-disabled
    requests.post(url, verify=False)

def case_3():
    # ok: tls-verification-disabled
    requests.get(url, verify=True)

def case_4():
    # todoruleid: tls-verification-disabled
    requests.get(url, **dict(verify=False))

