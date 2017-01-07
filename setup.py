#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2016, 2017 Kairo Araujo
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from os.path import dirname, join
from setuptools import setup, find_packages

with open(join(dirname(__file__), 'VERSION'), 'rb') as f:
    version = f.read().decode('ascii').strip()

setup(
    name="saassist-server",
    version=version,
    description="Security APAR Assistance Server",
    long_description=open('README.rst').read(),
    author="Kairo Araujo",
    author_email="kairo@kairo.eti.br",
    maintainer="Kairo Araujo",
    maintainer_email="kairo@kairo.eti.br",
    url="https://github.com/kairoaraujo/SAAssist/saassist-server",
    keywords="APAR Security Assistance Server Python FLRT IBM AIX VIOS PowerVM"
             "saassist-server SAAssist",
    packages=find_packages(exclude=['*.test', 'tests.*']),
    package_data={'': ['license.txt', 'VERSION']},
    include_package_data=True,
    license='Apache',
    platforms='Posix; MacOS X; Linux',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Information Technology',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: POSIX :: AIX',
        'Operating System :: POSIX :: PowerVM',
        'Operating System :: POSIX :: Linux',
        'Topic :: System :: Software Distribution',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
