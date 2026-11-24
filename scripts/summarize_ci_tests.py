"""Publish test outcomes without captured output, exception text or parametrized values."""
from pathlib import Path
from xml.etree import ElementTree as ET
import sys

path = Path(sys.argv[1])
if path.exists():
    raw = ET.parse(path)
    suite = ET.Element("testsuite", name="PySentry")
    for index, case in enumerate(raw.iter("testcase"), start=1):
        name = case.get("name","test").partition("[")[0]
        public = ET.SubElement(suite,"testcase", name=f"{name} ({index})", classname=case.get("classname",""))
        for status in ("failure","error","skipped"):
            if case.find(status) is not None:
                ET.SubElement(public,status)
    ET.ElementTree(suite).write(Path(sys.argv[2]),encoding="utf-8",xml_declaration=True)
