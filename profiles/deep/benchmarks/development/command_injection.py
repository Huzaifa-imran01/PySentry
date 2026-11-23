import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: request-shell-command
    os.system(request.args.get("cmd"))

def case_2():
    value = request.form.get("cmd")
    # ruleid: request-shell-command
    subprocess.run(value, shell=True)

def case_3():
    # ok: request-shell-command
    subprocess.run(["echo", request.args.get("cmd")], shell=False)

def case_4():
    # todoruleid: request-shell-command
    execute_in_other_module(request.args.get("cmd"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def execute_in_other_module(value):
    return os.system(value)
def custom_runner(value):
    return os.system(value)
