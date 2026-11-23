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
    # ruleid: framework-yaml
    yaml.unsafe_load(data)
    # ok: framework-yaml
    yaml.safe_load(data)

async def handle(req: Request):
    data = req.query_params.get("q")
    # ruleid: framework-yaml
    yaml.load(data, Loader=yaml.UnsafeLoader)

def ordinary(data: str):
    # ok: framework-yaml
    yaml.unsafe_load(data)
