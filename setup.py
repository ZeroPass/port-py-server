#!/usr/bin/env python3
import os
import sys
from setuptools import setup, find_packages
__package_name__ = "port-py-server"
__version__      = '0.15.1'
__summery__      = 'Python implementation of Port server SDK'

base_dir = os.path.dirname(__file__)
src_dir  = os.path.join(base_dir, "src")

# When executing the setup.py, we need to be able to import ourselves, this
# means that we need to add the src/ directory to the sys.path.
sys.path.insert(0, src_dir)

setup(
    name=__package_name__,
    version=__version__,
    description=__summery__,
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    include_package_data=True,
    python_requires=">=3.9.11",
    install_requires=[
        'coloredlogs>=15.0.1',
        'json-rpc>=1.13.0',
        'ldif>=4.1.2',
        'orjson>=3.6.7',
        'pycountry>=22.3.5',
        'pymrtd@git+https://github.com/ZeroPass/pymrtd.git@master',
        'pywin32>=303;platform_system=="Windows"',
        'sqlalchemy>=1.4.32,<2.0',
        'starlette>=0.19.0',
        'uvicorn[standard]>=0.17.6',
        'asgiref>=3.5.2'
    ],
    extras_require={
        'examples' : [
            'PyYAML>=6.0',
            'requests>=2.27.1'
        ],
        'mysql' : ['mysqlclient>=2.1.0'], # for using MySQL DB
        'postgresql' : ['psycopg2>=2.9.3'], # for using PostgreSQL DB
        'sqlite' : ['sqlcipher3>=0.4.5'], # for using SQLite
        'tests': [
            'pytest>=7.1.0',
            'pytest-depends>=1.0.1',
            'pytest-datafiles>=2.0.0'
        ],
    }
)
