from setuptools import setup
from pathlib import Path

here = Path(__file__).parent
reqs = []
try:
    req_text = (here / "requirements.txt").read_text(encoding="utf-8")
    for ln in req_text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        reqs.append(ln)
except Exception:
    reqs = []

setup(
    name="DorkDigger",
    version="0.1.0",
    description="Simple dork monitoring tool",
    py_modules=["DorkDigger"],
    install_requires=reqs,
    entry_points={
        'console_scripts': [
            'DorkDigger = DorkDigger:main_cli',
        ],
    },
)
