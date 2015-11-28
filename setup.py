#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name='signxml',
    version='0.4.6',
    url='https://github.com/kislyuk/signxml',
    license='Apache Software License',
    author='Andrey Kislyuk',
    author_email='kislyuk@gmail.com',
    description='Python XML Signature library',
    long_description=open('README.rst').read(),
    install_requires=[
        'lxml >= 3.4.4, < 3.5',
        'defusedxml >= 0.4.1, < 0.5',
        'eight >= 0.3.0, < 0.4',
        'cryptography >= 1.0.2, < 1.1',
        'pyOpenSSL >= 0.15.1',
        'certifi >= 2015.9.6.2'
    ],
    extras_require={
        ':python_version == "2.7"': ['enum34 >= 1.0.4'],
        ':python_version == "3.3"': ['enum34 >= 1.0.4']
    },
    packages = find_packages(exclude=['test']),
    platforms=['MacOS X', 'Posix'],
    package_data={'signxml': ['schemas/*.xsd']},
    zip_safe=False,
    include_package_data=True,
    classifiers=[
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: MacOS :: MacOS X',
        'Operating System :: POSIX',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
