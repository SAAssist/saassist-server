Security APAR Assistant installation
====================================



saassist-server Installation
****************************

As requisites to install the saassist-server is necessary Python version 3 and
BeautifulSoup4 module.

Installing Python 3
-------------------

Python version 3 is required by saassist-server and can run on Linux, AIX and
MacOS (Windows I have never tried, but I guess is possible also).

Follow bellow the instructions for Linux and AIX.

LINUX
^^^^^

To install Python 3 use yum or apt-get of your distribution, also install pip3

``yum install python3 pip3``

AIX
^^^

I have been using this Python3 package to my environment that can be installed
using ``smitty install``

http://www.aixtools.net/index.php/python3


Installing BeautifulSoup4
-------------------------

BeautifulSoup is a Python package (module) and is required for saassist-server.
It can be installed using PIP

PIP
^^^

``pip3 install bs4``

Installing saassist-server
--------------------------

To install saassist-server you need to download the latest version, extract the
content and config the server_config.py file.

1. Download

    http://github.com/SAAssist/saassist-server


2. Extract

    .zip ``unzip saassist-server[version].zip``

    .tar ``tar xvf saassist-server[version].zip``

4. Configure the server_config.py

    All comments about the necessary information are inside of file.

    ``vi server_config.py``

saassist-client Installation
****************************

If you want to use HTTP protocol, remember the package curl is required for IBM
AIX/PowerVM.

Download the saassist-client from the link, extract the files and configure
the client_config file.

1. Download

    http://github.com/SAAssist/saassist-client

2. Extract the files

    .zip ``unzip saassist-client[version].zip``

    .tar ``tar xvf saassist-client[version].zip``

4. Configure the client_config

    All comments about the necessary information are inside of file.

    ``vi client_config``
