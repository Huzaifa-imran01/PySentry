import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: client-controlled-payment-amount
    stripe.PaymentIntent.create(amount=request.args.get("amount"), currency="usd")

def case_2():
    amount = request.form.get("amount")
    # ruleid: client-controlled-payment-amount
    stripe.PaymentIntent.create(amount=amount, currency="usd")

def case_3():
    # ok: client-controlled-payment-amount
    stripe.PaymentIntent.create(amount=server_price, currency="usd")

def case_4():
    # todoruleid: client-controlled-payment-amount
    custom_checkout(request.args.get("amount"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def custom_checkout(value):
    return stripe.PaymentIntent.create(amount=value, currency="usd")
def custom_payment(value):
    return stripe.PaymentIntent.create(amount=value, currency="usd")
