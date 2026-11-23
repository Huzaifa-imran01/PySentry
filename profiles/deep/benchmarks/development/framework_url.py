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
    # ruleid: framework-url
    httpx.get(data)
    # ok: framework-url
    httpx.get("https://example.org", params={"q": data})

async def handle(req: Request):
    data = req.query_params.get("q")
    # ruleid: framework-url
    urllib.request.urlopen(data)

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

import aiohttp

async def fetch(req: Request, session: aiohttp.ClientSession):
    data = req.path_params["url"]
    # ruleid: framework-url
    await session.get(data)
    # ok: framework-url
    await session.get("https://example.org", params={"q": data})
