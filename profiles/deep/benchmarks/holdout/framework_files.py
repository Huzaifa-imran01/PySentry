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
    # ruleid: framework-files
    pathlib.Path(data).write_text("ok")
    # ok: framework-files
    pathlib.Path("out").write_text(data)

async def handle(req: Request):
    data = await req.body()
    # ruleid: framework-files
    pathlib.Path(data).read_bytes()

def ordinary(data: str):
    # ok: framework-files
    pathlib.Path(data).read_bytes()

@app.post("/upload")
async def upload(dest: str = fastapi.Form(...)):
    # ruleid: framework-files
    pathlib.Path(dest).write_bytes(b"sample")

async def read_input(stream: fastapi.UploadFile):
    name = await stream.read()
    # ruleid: framework-files
    pathlib.Path(name).read_bytes()


def query_value(request: Request):
    return request.query_params.get("selection")


async def delegated(request: Request):
    value = query_value(request)
    # todoruleid: framework-files
    pathlib.Path(value).read_bytes()
