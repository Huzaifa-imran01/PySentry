import ast, os, builtins, subprocess, pickle, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request

def holdout_0(request):
    name = request.GET.get("name")
    sql = "SELECT name FROM users WHERE name = "+name
    # ruleid: request-sql-query
    return db.execute(sql)

def holdout_1(request):
    # ok: request-sql-query
    return db.execute("SELECT name FROM users WHERE name = ?", (request.GET.get("name"),))

def holdout_2(request):
    # todoruleid: request-sql-query
    return query_helper(request.GET.get("name"))


# Known-limit helpers: unsafe behavior behind a function boundary.
def query_from_other_module(cursor):
    return execute_query(cursor, request.args.get("name"))
def execute_query(cursor, value):
    return cursor.execute("SELECT * FROM users WHERE name=" + value)
def query_helper(value):
    return db.execute("SELECT * FROM users WHERE name=" + value)
