#!/usr/bin/env python3
import os
import sys
from setuptools import setup, find_packages
__package_name__ = "port-py-server"
__version__      = '0.12.0'
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
    python_requires=">=3.9",
    install_requires=[
        'coloredlogs>=15.0.1',
        'cryptography>=3.4.7',
        'json-rpc>=1.13.0',
        'ldif3>=3.2.2',
        'orjson>=3.6.3',
        'pycountry>=20.7.3',
        'pymrtd>=0.6.2',
        'pywin32>=301;platform_system=="Windows"',
        'sqlalchemy>=1.4.23',
        'starlette>=0.16.0',
        'uvicorn[standard]>=0.15.0'
    ],
    extras_require={
        'examples' : [
            'PyYAML>=5.4.1 ',
            'requests>=2.26.0'
        ],
        'mysql' : ['mysqlclient>=2.0.3'], # for using MySQL DB
        'postgresql' : ['psycopg2>=2.9.1'], # for using PostgreSQL DB
        'sqlite' : ['sqlcipher3>=0.4.5'], # for using SQLite
        'tests': [
            'pytest>=6.2.4',
            'pytest-depends>=1.0.1',
            'pytest-datafiles>=2.0.0'
        ],
    }
)
