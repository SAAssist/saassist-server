#!/usr/bin/env python3
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

# Security APAR assistent installation path
saassist_home = '/saassist-server'

# Proxy Server
# If saassist-server needs to access IBM Fix Level Recommendation Tool through
# a proxy server is necessary specify the proxy server.
# (Empty or proxy = 'http://proxyserver:3128')
proxy = ''

# SSL Unverified Context.
# Just change it if you are having troubles with SSL errors.
ssl_context=False

# Security APAR assistant Web Server Port
# If you decide to use the included webserver (saassist-webserver.py) specify
# here the port number that you want to use.
saassist_web_port = 8000

# Cache File for FLRT
# Define how long you want to use cache file without update.
# It is defined in seconds, default is 1 day = 86400 seconds.
cache_time = 86400

# IBM Fix Level Recommendation Tool URL
# Is not recommended to change. Edit it only if necessary/required
flrt_url = 'https://www14.software.ibm.com/support/customercare/flrt/doc?page=aparCSV'
