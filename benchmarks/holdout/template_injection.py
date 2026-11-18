import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    source = request.GET.get("source")
    # ruleid: request-template-code
    return flask.render_template_string(source)

def holdout_1(request):
    # ok: request-template-code
    return flask.render_template("safe.html", value=request.GET.get("source"))

def holdout_2(request):
    # todoruleid: request-template-code
    return other_engine(request.GET.get("source"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def custom_template_engine(value):
    return flask.render_template_string(value)
def other_engine(value):
    return flask.render_template_string(value)
