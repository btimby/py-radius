#!/bin/env python

from distutils.core import setup

exec(open('radius/__version__.py').read())  # not possible to import at install time

name = 'py-radius'
release = '1'
versrel = __version__ + '-' + release
download_url = 'https://github.com/downloads/btimby/' + name + \
                           '/' + name + '-' + versrel + '.tar.gz'

with open('LICENSE', 'r') as l:
    license = l.read()


with open('requirements.txt') as f:
    install_requires = [line.strip() for line in f]


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
    url = 'http://github.com/btimby/' + name + '/',
    download_url = download_url,
    license = license,
    packages = ["radius"],
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
    ],
    install_requires=install_requires,
)
