#!/usr/bin/env python
# -*- coding:utf-8 -*-

from setuptools import setup, find_packages

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name="NauNetTools",
    version='0.0.1',
    keywords=['Network Tools', 'Nau', 'Nanjing Audit University'],
    description='Network tools for Nanjing Audit University',
    long_description_content_type='text/markdown',
    long_description=long_description,
    license='GPLv3',

    url='https://github.com/XClare/NauNetTools',
    author='XClare',
    author_email='x.clare9326@gmail.com',
    maintainer='XClare',
    maintainer_email='x.clare9326@gmail.com',

    packages=find_packages(),
    include_package_data=True,
    platforms='any',
    install_requires=['requests', 'bs4', 'pycryptodome'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GPLv3 License",
        "Operating System :: OS Independent",
    ],
)
