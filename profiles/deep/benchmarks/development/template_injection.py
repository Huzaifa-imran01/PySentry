import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: request-template-code
    flask.render_template_string(request.args.get("template"))

def case_2():
    template = request.form.get("template")
    # ruleid: request-template-code
    flask.render_template_string(template)

def case_3():
    # ok: request-template-code
    flask.render_template("fixed.html", value=request.args.get("value"))

def case_4():
    # todoruleid: request-template-code
    custom_template_engine(request.args.get("template"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def custom_template_engine(value):
    return flask.render_template_string(value)
def other_engine(value):
    return flask.render_template_string(value)
