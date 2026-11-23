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
    # ruleid: framework-url
    urllib.request.urlopen(data)
    # ok: framework-url
    httpx.get("https://example.org", params={"q": data})

async def handle(req: Request):
    data = await req.body()
    # ruleid: framework-url
    httpx.get(data)

def ordinary(data: str):
    # ok: framework-url
    httpx.get(data)

import pydantic

class Payload(pydantic.BaseModel):
    url: str

@app.post("/lookup")
async def lookup(payload: Payload):
    # ruleid: framework-url
    httpx.get(payload.url)


def query_value(request: Request):
    return request.query_params.get("selection")


async def delegated(request: Request):
    value = query_value(request)
    # todoruleid: framework-url
    httpx.get(value)
