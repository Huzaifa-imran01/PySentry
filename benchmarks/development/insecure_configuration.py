import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: django-debug-enabled
    DEBUG = True

def case_2():
    # ruleid: django-debug-enabled
    DEBUG = True

def case_3():
    # ok: django-debug-enabled
    DEBUG = False

def case_4():
    # todoruleid: django-debug-enabled
    DEBUG = bool(os.environ.get("DEBUG"))

