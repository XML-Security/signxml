#!/usr/bin/env python

from setuptools import find_packages, setup

setup(
    name="signxml",
    version="3.1.0",
    url="https://github.com/kislyuk/signxml",
    license="Apache Software License",
    author="Andrey Kislyuk",
    author_email="kislyuk@gmail.com",
    description="Python XML Signature and XAdES library",
    long_description=open("README.rst").read(),
    python_requires=">=3.7",
    install_requires=[
        # Dependencies are restricted by major version range according to semver.
        # By default, version minimums are set to be compatible with the oldest supported Ubuntu LTS (currently 18.04).
        "lxml >= 4.2.1, < 5",
        "cryptography >= 3.4.8",  # Set to the version in Ubuntu 22.04 due to features we need from cryptography 3.1
        "pyOpenSSL >= 17.5.0",
        "certifi >= 2018.1.18",
    ],
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
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
