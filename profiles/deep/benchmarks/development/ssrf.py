import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: request-outbound-url
    requests.get(request.args.get("url"))

def case_2():
    url = request.form.get("url")
    # ruleid: request-outbound-url
    requests.post(url)

def case_3():
    # ok: request-outbound-url
    requests.get("https://example.com", params={"q":request.args.get("q")})

def case_4():
    # todoruleid: request-outbound-url
    custom_http_client(request.args.get("url"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def custom_http_client(value):
    return requests.get(value)
def http_wrapper(value):
    return requests.get(value)
