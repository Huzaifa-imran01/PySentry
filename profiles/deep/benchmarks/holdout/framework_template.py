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
    # ruleid: framework-template
    jinja2.Template(source=data)
    # ok: framework-template
    jinja2.Template("hello").render(name=data)

async def handle(req: Request):
    data = await req.body()
    # ruleid: framework-template
    jinja2.Template(data)

def ordinary(data: str):
    # ok: framework-template
    jinja2.Template(data)


def query_value(request: Request):
    return request.query_params.get("selection")


async def delegated(request: Request):
    value = query_value(request)
    # todoruleid: framework-template
    jinja2.Template(value)
