import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: request-unsafe-html
    markupsafe.Markup(request.args.get("html"))

def case_2():
    # ruleid: request-unsafe-html
    django.utils.safestring.mark_safe(request.form.get("html"))

def case_3():
    # ok: request-unsafe-html
    markupsafe.Markup(markupsafe.escape(request.args.get("html")))

def case_4():
    # todoruleid: request-unsafe-html
    unsafe_renderer(request.args.get("html"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def unsafe_renderer(value):
    return markupsafe.Markup(value)
def custom_mark_safe(value):
    return markupsafe.Markup(value)
