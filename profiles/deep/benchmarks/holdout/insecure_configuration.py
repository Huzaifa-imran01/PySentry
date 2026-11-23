import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    # ruleid: django-debug-enabled
    DEBUG = True

def holdout_1(request):
    # ok: django-debug-enabled
    DEBUG = False

def holdout_2(request):
    # todoruleid: django-debug-enabled
    DEBUG = bool(os.environ.get("DEBUG", "0"))

