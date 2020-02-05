#!/usr/bin/env bash

sh build.sh

twine check dist/*

twine upload -r coding-pypi-nau_net_tools-release dist/*