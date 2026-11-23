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
    # ruleid: framework-files
    pathlib.Path(data).read_bytes()
    # ok: framework-files
    pathlib.Path("out").write_text(data)

async def handle(req: Request):
    data = req.query_params.get("q")
    # ruleid: framework-files
    pathlib.Path(data).write_text("ok")

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

import tarfile

async def extract(req: Request, archive: tarfile.TarFile):
    form = await req.form()
    data = form["folder"]
    # ruleid: framework-files
    archive.extractall(path=data)
    # ok: framework-files
    archive.extractall(path="/fixed", filter="data")
