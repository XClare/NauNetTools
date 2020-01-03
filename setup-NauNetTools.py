#!/usr/bin/env python
# -*- coding:utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="NauNetTools",
    version='0.0.1',
    keywords=('Network Tools', 'Nau', 'Nanjing Audit University'),
    description='Network tools for Nanjing Audit University',
    long_description='Network tools for Nanjing Audit University. '
                     'Now including SSO and educational administration login client. '
                     'These tools may help you custom your own university website spider.',
    license='GPLv3',

    url='https://github.com/XClare/NauNetTools',
    author='XClare',
    author_email='x.clare9326@gmail.com',

    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    install_requires=['requests', 'bs4', 'pycryptodome']
)
