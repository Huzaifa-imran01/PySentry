import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    # ruleid: weak-digest
    return hashlib.sha1(value).hexdigest()

def holdout_1(request):
    # ok: weak-digest
    return hashlib.sha256(value).hexdigest()

def holdout_2(request):
    # todoruleid: weak-digest
    return hashlib.new("md5", value).hexdigest()

