import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: unsafe-deserialization
    pickle.loads(payload)

def case_2():
    # ruleid: unsafe-deserialization
    yaml.unsafe_load(payload)

def case_3():
    # ok: unsafe-deserialization
    json.loads(payload)

def case_4():
    # todoruleid: unsafe-deserialization
    getattr(pickle, "loads")(payload)

