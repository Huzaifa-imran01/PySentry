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
    # ruleid: framework-template
    jinja2.Template(data)
    # ok: framework-template
    jinja2.Template("hello").render(name=data)

async def handle(req: Request):
    data = req.query_params.get("q")
    # ruleid: framework-template
    jinja2.Template(source=data)

def ordinary(data: str):
    # ok: framework-template
    jinja2.Template(data)



async def render(req: fastapi.Request, env: jinja2.Environment):
    data = await req.body()
    # ruleid: framework-template
    env.from_string(data)
    # ok: framework-template
    env.from_string("Hello {{ user }}").render(user=data)
