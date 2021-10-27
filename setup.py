#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='signxml',
    version="2.9.0",
    url='https://github.com/kislyuk/signxml',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description='Python XML Signature library',
    long_description=open('README.rst').read(),
    install_requires=[
        # Dependencies are restricted by major version range according to semver.
        # By default, version minimums are set to be compatible with the oldest supported Ubuntu LTS (currently 18.04).
        'lxml >= 4.2.1, < 5',
        'cryptography >= 2.1.4',
        'pyOpenSSL >= 17.5.0, < 21',
        'certifi >= 2018.1.18'
    ],
    packages=find_packages(exclude=['test']),
    platforms=['MacOS X', 'Posix'],
    package_data={'signxml': ['schemas/*.xsd']},
    include_package_data=True,
    test_suite='test',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
