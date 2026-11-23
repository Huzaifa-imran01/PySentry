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
    # ruleid: framework-shell
    subprocess.run(data, shell=True)
    # ok: framework-shell
    subprocess.run(["echo", data], shell=False)

async def handle(req: Request):
    data = req.query_params.get("q")
    # ruleid: framework-shell
    subprocess.check_output(data, shell=True)

def ordinary(data: str):
    # ok: framework-shell
    subprocess.run(data, shell=True)
