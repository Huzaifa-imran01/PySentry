import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    # ruleid: hardcoded-password
    secret_key = "literal-example"

def holdout_1(request):
    # ok: hardcoded-password
    secret_key = os.environ["SECRET_KEY"]

def holdout_2(request):
    # todoruleid: hardcoded-password
    credentials = {"password": "example-only"}

