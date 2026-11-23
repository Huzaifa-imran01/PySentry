import fastapi
from starlette.requests import Request
import sqlalchemy
import httpx
import urllib.request
import pathlib
import subprocess
import jinja2
import yaml

app = fastapi.FastAPI()

@app.get("/sample")
async def endpoint(data: str):
    # ruleid: framework-sql
    sqlalchemy.text(data)
    # ok: framework-sql
    cursor.execute("SELECT %s", [data])

async def handle(req: Request):
    data = req.query_params.get("q")
    # ruleid: framework-sql
    cursor.execute(data)

def ordinary(data: str):
    # ok: framework-sql
    sqlalchemy.text(data)



async def records(req: Request):
    body = await req.json()
    data = body["q"]
    # ruleid: framework-sql
    Entry.objects.raw(data)
    # ok: framework-sql
    Entry.objects.raw("SELECT * FROM entries WHERE id=%s", [data])
