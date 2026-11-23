import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    expression = request.POST.get("expression")
    # ruleid: insecure-eval
    return eval(expression)

def holdout_1(request):
    # ok: insecure-eval
    return ast.literal_eval("[1, 2]")

def holdout_2(request):
    # todoruleid: insecure-eval
    return getattr(builtins, operation)(expression)

