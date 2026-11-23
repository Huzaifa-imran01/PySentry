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

@app.post("/sample")
async def endpoint(data: str):
    # ruleid: framework-sql
    cursor.execute(data)
    # ok: framework-sql
    cursor.execute("SELECT %s", [data])

async def handle(req: Request):
    data = await req.body()
    # ruleid: framework-sql
    sqlalchemy.text(data)

def ordinary(data: str):
    # ok: framework-sql
    sqlalchemy.text(data)


def query_value(request: Request):
    return request.query_params.get("selection")


async def delegated(request: Request):
    value = query_value(request)
    # todoruleid: framework-sql
    sqlalchemy.text(value)
