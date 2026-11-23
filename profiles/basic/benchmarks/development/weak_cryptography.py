import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: weak-digest
    hashlib.md5(payload)

def case_2():
    # ruleid: weak-digest
    hashlib.sha1(payload)

def case_3():
    # ok: weak-digest
    hashlib.sha256(payload)

def case_4():
    # todoruleid: weak-digest
    hashlib.new("md5", payload)

