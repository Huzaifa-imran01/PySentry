import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    # ruleid: unsafe-deserialization
    return pickle.load(stream)

def holdout_1(request):
    # ok: unsafe-deserialization
    return json.load(stream)

def holdout_2(request):
    # todoruleid: unsafe-deserialization
    return getattr(pickle, "load")(stream)

