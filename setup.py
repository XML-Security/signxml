#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="signxml",
    version="4.0.2",
    url="https://github.com/kislyuk/signxml",
    license="Apache Software License",
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Python XML Signature and XAdES library",
    long_description=open("README.rst").read(),
    python_requires=">=3.7",
    install_requires=[
        "lxml >= 5.2.1, < 6",  # Ubuntu 24.04 LTS
        "cryptography >= 43",  # Required to support client certificate validation
        "certifi >= 2023.11.17",  # Ubuntu 24.04 LTS
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
