import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    # ruleid: tls-verification-disabled
    return requests.post("https://example.com", verify=False, timeout=5)

def holdout_1(request):
    # ok: tls-verification-disabled
    return requests.post("https://example.com", verify=True)

def holdout_2(request):
    # todoruleid: tls-verification-disabled
    return requests.get(url, **dict(verify=False))

