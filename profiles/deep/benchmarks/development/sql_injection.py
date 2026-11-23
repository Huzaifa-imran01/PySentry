import ast, builtins, os, subprocess, pickle, yaml, json, hashlib, requests, flask, markupsafe, html, jwt, stripe
import django.views.decorators.csrf
import django.utils.safestring
import urllib.request
from flask import request

def case_1():
    # ruleid: request-sql-query
    cursor.execute("SELECT * FROM users WHERE name=" + request.args.get("name"))

def case_2():
    query = f"SELECT * FROM users WHERE name={request.form.get('name')}"
    # ruleid: request-sql-query
    cursor.execute(query)

def case_3():
    # ok: request-sql-query
    cursor.execute("SELECT * FROM users WHERE name=%s", (request.args.get("name"),))

def case_4():
    # todoruleid: request-sql-query
    query_from_other_module(cursor)


# Known-limit helpers: unsafe behavior behind a function boundary.
def query_from_other_module(cursor):
    return execute_query(cursor, request.args.get("name"))
def execute_query(cursor, value):
    return cursor.execute("SELECT * FROM users WHERE name=" + value)
def query_helper(value):
    return db.execute("SELECT * FROM users WHERE name=" + value)
