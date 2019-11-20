#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='signxml',
    version="2.6.0",
    url='https://github.com/kislyuk/signxml',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description='Python XML Signature library',
    long_description=open('README.rst').read(),
    install_requires=[
        'lxml >= 4.4.1, < 5',
        'defusedxml >= 0.6.0, < 1',
        'eight >= 0.4.2, < 1',
        'cryptography >= 2.8, < 3',
        'asn1crypto >= 1.2.0',
        'pyOpenSSL >= 18.0.0, < 19',
        'certifi >= 2019.9.11'
    ],
    extras_require={
        ':python_version == "2.7"': [
            'enum34 >= 1.1.6, < 2',
            'ipaddress >= 1.0.17, < 2'
        ]
    },
    packages=find_packages(exclude=['test']),
    platforms=['MacOS X', 'Posix'],
    package_data={'signxml': ['schemas/*.xsd']},
    zip_safe=False,
    include_package_data=True,
    test_suite='test',
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
