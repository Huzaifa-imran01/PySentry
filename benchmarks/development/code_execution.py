import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: insecure-eval
    eval(user_input)

def case_2():
    # ruleid: insecure-eval
    eval(other_input)

def case_3():
    # ok: insecure-eval
    ast.literal_eval(user_input)

def case_4():
    # todoruleid: insecure-eval
    getattr(builtins, "ev" + "al")(user_input)

