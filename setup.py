# stdlib
import os
import re
import sys

# pypi
from setuptools import find_packages
from setuptools import setup

# ==============================================================================


HERE = os.path.abspath(os.path.dirname(__file__))

# store version in the init.py
with open(
    os.path.join(HERE, "src", "metadata_parser", "__init__.py")
) as v_file:  # noqa: E501
    VERSION = (
        re.compile(r'.*__VERSION__ = "(.*?)"', re.S).match(v_file.read()).group(1)
    )  # noqa: E501

long_description = description = (
    "A module to parse metadata out of urls and html documents"
)
with open(os.path.join(HERE, "README.rst")) as fp:
    long_description = fp.read()

requires = [
    "BeautifulSoup4>4.13.0,<4.14.0",
    "requests>=2.19.1",
    "requests-toolbelt>=0.8.0",
    "typing_extensions",
]
if sys.version_info.major == 2:
    requires.append("backports.html")

if sys.version_info >= (3, 13):
    requires.append("legacy-cgi")

tests_require = [
    "httpbin",
    "pytest",
    "pytest-httpbin",
    "responses",
    "tldextract",
    "types-beautifulsoup4",
    "types-requests",
    "werkzeug<2.1.0",  # httpbin compat issue
]
testing_extras = tests_require + []

# go
setup(
    name="metadata_parser",
    version=VERSION,
    description=description,
    long_description=long_description,
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Text Processing :: Markup :: HTML",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords="opengraph protocol facebook",
    author="Jonathan Vanasco",
    author_email="jonathan@findmeon.com",
    url="https://github.com/jvanasco/metadata_parser",
    license="MIT",
    test_suite="tests",
    packages=find_packages(
        where="src",
    ),
    package_dir={"": "src"},
    package_data={"metadata_parser": ["py.typed"]},
    include_package_data=True,
    zip_safe=False,
    install_requires=requires,
    tests_require=tests_require,
    extras_require={
        "testing": testing_extras,
    },
    entry_points="""
      # -*- Entry points: -*-
      """,
)
