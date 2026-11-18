import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    amount = request.POST.get("price")
    # ruleid: client-controlled-payment-amount
    return stripe.PaymentIntent.create(currency="eur", amount=amount)

def holdout_1(request):
    # ok: client-controlled-payment-amount
    return stripe.PaymentIntent.create(currency="eur", amount=server_price)

def holdout_2(request):
    # todoruleid: client-controlled-payment-amount
    return custom_payment(request.POST.get("price"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def custom_checkout(value):
    return stripe.PaymentIntent.create(amount=value, currency="usd")
def custom_payment(value):
    return stripe.PaymentIntent.create(amount=value, currency="usd")
