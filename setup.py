#!/bin/env python

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import radius

name = 'py-radius'
version = radius.__version__
release = '1'
versrel = version + '-' + release

with open('LICENSE', 'r') as l:
    license = l.read()

setup(
    name = name,
    version = versrel,
    description = 'RADIUS authentication module',
    long_description = 'A pure Python module that implements client side RADIUS ' \
                       'authentication, as defined by RFC2865.',
    author = 'Stuart Bishop',
    author_email = 'zen@shangri-la.dropbear.id.au',
    maintainer = 'Ben Timby',
    maintainer_email = 'btimby@gmail.com',
    url = 'https://github.com/btimby/' + name + '/',
    license = license,
    py_modules = ["radius"],
    classifiers = [
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.0',
        'Programming Language :: Python :: 3.1',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ]
)
