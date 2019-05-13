#!/bin/env python

from distutils.core import setup
import radius

name = 'py-radius'
version = radius.__version__
release = '1'
versrel = version + '-' + release
download_url = 'https://github.com/downloads/btimby/' + name + \
                           '/' + name + '-' + versrel + '.tar.gz'

with open('README.rst', 'r') as rm:
    long_description = rm.read()

setup(
    name = name,
    version = versrel,
    description = 'RADIUS authentication module',
    long_description=long_description,
    author = 'Stuart Bishop',
    author_email = 'zen@shangri-la.dropbear.id.au',
    maintainer = 'Ben Timby',
    maintainer_email = 'btimby@gmail.com',
    url = 'http://github.com/btimby/' + name + '/',
    download_url = download_url,
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
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: System :: Systems Administration :: Authentication/Directory',
    ]
)
