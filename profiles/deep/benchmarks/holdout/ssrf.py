import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    destination = request.GET.get("destination")
    # ruleid: request-outbound-url
    return urllib.request.urlopen(destination)

def holdout_1(request):
    # ok: request-outbound-url
    return requests.post("https://example.com", data=request.POST.get("data"))

def holdout_2(request):
    # todoruleid: request-outbound-url
    return http_wrapper(request.GET.get("destination"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def custom_http_client(value):
    return requests.get(value)
def http_wrapper(value):
    return requests.get(value)
