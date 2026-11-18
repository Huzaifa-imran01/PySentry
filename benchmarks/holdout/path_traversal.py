import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    name = request.GET.get("filename")
    # ruleid: request-file-path
    return open("/uploads/" + name)

def holdout_1(request):
    # ok: request-file-path
    return open("/uploads/fixed.txt")

def holdout_2(request):
    # todoruleid: request-file-path
    return storage.download(request.GET.get("filename"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def read_in_other_module(value):
    return open(value)
class storage:
    @staticmethod
    def download(value):
        return open(value)
