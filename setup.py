#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="signxml",
    version="3.2.2",
    url="https://github.com/kislyuk/signxml",
    license="Apache Software License",
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Python XML Signature and XAdES library",
    long_description=open("README.rst").read(),
    python_requires=">=3.7",
    install_requires=[
        # Dependencies are restricted by major version range according to semver.
        # By default, version minimums are set to be compatible with the oldest supported Ubuntu LTS (currently 20.04).
        "lxml >= 4.5.0, < 6",
        "cryptography >= 3.4.8",  # Set to the version in Ubuntu 22.04 due to features we need from cryptography 3.1
        "pyOpenSSL >= 19.0.0",
        "certifi >= 2019.11.28",
        # "tsp-client >= 0.1.3",
    ],
    extras_require={
        "tests": [
            "ruff",
            "coverage",
            "build",
            "wheel",
            "mypy",
            "lxml-stubs",
        ]
    },
    packages=find_packages(exclude=["test"]),
    platforms=["MacOS X", "Posix"],
    package_data={"signxml": ["schemas/*.xsd", "py.typed"]},
    include_package_data=True,
    test_suite="test",
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
