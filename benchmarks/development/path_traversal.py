import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: request-file-path
    open(request.args.get("path"))

def case_2():
    path = request.form.get("path")
    # ruleid: request-file-path
    flask.send_file(path)

def case_3():
    # ok: request-file-path
    open("fixed.txt")

def case_4():
    # todoruleid: request-file-path
    read_in_other_module(request.args.get("path"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def read_in_other_module(value):
    return open(value)
class storage:
    @staticmethod
    def download(value):
        return open(value)
