import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    value = request.POST.get("html")
    # ruleid: request-unsafe-html
    return django.utils.safestring.mark_safe(value)

def holdout_1(request):
    # ok: request-unsafe-html
    return markupsafe.Markup(html.escape(request.GET.get("html")))

def holdout_2(request):
    # todoruleid: request-unsafe-html
    return custom_mark_safe(request.GET.get("html"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def unsafe_renderer(value):
    return markupsafe.Markup(value)
def custom_mark_safe(value):
    return markupsafe.Markup(value)
