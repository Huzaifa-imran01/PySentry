import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: hardcoded-password
    password = "example-password"

def case_2():
    # ruleid: hardcoded-password
    PASSWORD = "another-example"

def case_3():
    # ok: hardcoded-password
    password = os.environ["PASSWORD"]

def case_4():
    # todoruleid: hardcoded-password
    credentials = {"password": "example-only"}

