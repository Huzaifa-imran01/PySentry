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
    # ruleid: framework-yaml
    yaml.load(data, Loader=yaml.UnsafeLoader)
    # ok: framework-yaml
    yaml.safe_load(data)

async def handle(req: Request):
    data = await req.body()
    # ruleid: framework-yaml
    yaml.unsafe_load(data)

def ordinary(data: str):
    # ok: framework-yaml
    yaml.unsafe_load(data)


def query_value(request: Request):
    return request.query_params.get("selection")


async def delegated(request: Request):
    value = query_value(request)
    # todoruleid: framework-yaml
    yaml.unsafe_load(value)
