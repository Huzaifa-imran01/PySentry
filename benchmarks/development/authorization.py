import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: csrf-protection-disabled
    @django.views.decorators.csrf.csrf_exempt
    def endpoint(request):
        return update_account(request)

def case_2():
    # ruleid: csrf-protection-disabled
    @django.views.decorators.csrf.csrf_exempt
    def other(request):
        return delete_account(request)

def case_3():
    def endpoint(request):
    # ok: csrf-protection-disabled
        return update_account(request)

def case_4():
    def endpoint(request):
    # todoruleid: csrf-protection-disabled
        return Account.objects.get(id=request.GET.get("id"))

