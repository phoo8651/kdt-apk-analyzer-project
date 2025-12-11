#!/usr/bin/env python3

import re

import requests

from bs4 import BeautifulSoup as Soup
from bs4 import element


ANDROID_PERMISSION_DOCS_URL = (
    "https://developer.android.com/" "reference/android/Manifest.permission"
)

response = requests.get(ANDROID_PERMISSION_DOCS_URL, timeout=5)
content = Soup(response.content, "html.parser")

online_permissions = {}

# grab all the permissions from the online docs
permission_divs = content.find_all("div", {"data-version-added": re.compile(r"\d*")})
for pd in permission_divs:
    permission_name = pd.find("h3").contents[0]
    if permission_name in ["Constants", "Manifest.permission"]:
        continue
    try:
        protection_level = re.search(r"Protection level\: (\w+)", str(pd)).groups()[0]
    except AttributeError:
        protection_level = "normal"
    desc = []
    for a in pd.find("p").contents:
        if type(a) is element.NavigableString:
            desc.append(
                str(a).strip().replace("\n", "").replace("\t", "").replace("\xa0", "")
            )
        elif type(a) is element.Tag:
            if "Protection level:" in a.text:
                break
            desc.append(
                str(a.text)
                .strip()
                .replace("\n", "")
                .replace("\t", "")
                .replace("\xa0", "")
            )

    description = " ".join(desc)
    online_permissions[permission_name] = [protection_level, "", description]

# check the permissions we currently have in dvm_permissions.py
# Avoid executing file contents with eval/compile; load module safely instead.
from pathlib import Path
import importlib.util

DVM_PERMISSIONS = {}
try:
    dvm_path = (
        Path(__file__).resolve().parent.parent
        / "mobsf"
        / "StaticAnalyzer"
        / "views"
        / "android"
        / "kb"
        / "dvm_permissions.py"
    )
    if dvm_path.exists():
        spec = importlib.util.spec_from_file_location("dvm_permissions", str(dvm_path))
        if spec and spec.loader:
            dvm_mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(dvm_mod)  # type: ignore
            DVM_PERMISSIONS = getattr(dvm_mod, "DVM_PERMISSIONS", {}) or {}
except Exception:
    # fall back to empty dict on any unexpected error
    DVM_PERMISSIONS = {}

MANIFEST_PERMISSIONS = DVM_PERMISSIONS.get("MANIFEST_PERMISSION", {})

for permission_name in online_permissions:
    if permission_name in MANIFEST_PERMISSIONS.keys():
        continue
    print("'{}': {},".format(permission_name, str(online_permissions[permission_name])))
