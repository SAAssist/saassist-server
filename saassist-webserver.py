#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# saassist-webserver.py
#
import http.server
import os
import socketserver
from server_config import saassist_home
from server_config import saassist_web_port

web_dir = os.path.join(os.path.dirname(__file__),
                       '{0}/saassist/data/repos'.format(saassist_home))
os.chdir(web_dir)

Handler = http.server.SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(("", saassist_web_port), Handler)
print("SAA Server is running at port", saassist_web_port)
httpd.serve_forever()
