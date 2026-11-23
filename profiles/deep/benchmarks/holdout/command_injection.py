import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    cmd = request.POST.get("command")
    # ruleid: request-shell-command
    return subprocess.Popen(cmd, shell=True)

def holdout_1(request):
    # ok: request-shell-command
    return subprocess.Popen(["echo", "constant"])

def holdout_2(request):
    # todoruleid: request-shell-command
    return custom_runner(request.POST.get("command"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def execute_in_other_module(value):
    return os.system(value)
def custom_runner(value):
    return os.system(value)
