***********************
Security APAR Assistant
***********************

:SAAssist: Security APAR Assistant
:License: Apache 2.0
:Development: https://github.com/SAAssist/


.. contents::
    :local:
    :depth: 3
    :backlinks: none

Overview
********

Security APAR Assist (SAAssist) is a tool to controls security APARs for IBM
AIX and IBM PowerVM environment.

There are two basic components on SAAssist, SAAssist Server (saassist-server)
and SAAssist Client (saassist-client).

This is a Open Source software licensed by Apache License 2.0.

Important:

The Security APAR Assistant (including saassist-server and saassist-client) is
not an IBM Inc. software and it is not supported or guaranteed by IBM.

IBM AIX, IBM PowerVM and IBM Fix Level Recommended Tool website are registered
trademarks of IBM Corporation in the United States, other countries, or both.

How it works
************

SAAssist Server (saassist-server) is the tool that works directly with the IBM
Fix Level Recommendation Tool (FLRT) website (
https://www-304.ibm.com/support/customercare/flrt/) and it creates a repository
with APARs information and packages based on CVE or IV number.

Those APARs information and packages are accessed by SAAssist Client
(saassist-client) by HTTP or NFS protocol and checks if the APAR affect the
server and if it can be installed.

Only the SAAssist Server needs to access the IBM FLRT website, proxy is also
supported and it can be used.
AAssist Client needs to access only SAAssist Server by HTTP or NFS.

Schema overvivew
 .. code-block::

     _________________
    |                 | --------------[ Internet ]--------[ IBM FLRT website ]
    | saassist server |               * web proxy
    |_________________|
            |
            |
            `----- [  Repository  ]
                   [  info, fixes ]
                   [  HTTP: :NFS  ]
                           |
            .--------------'
            |
    ________|_________
    |                 |
    | saassist client |
    |_________________|
            |
            |
            |`---- {check}    verifies if APAR is applicable & boot required
            |
            |`-----{info}     gets detailed information about APAR (asc file)
            |
             `-----{install}  installs APAR

    saassist-server: it can be an AIX, Linux or MacOS with Internet access
                     directly or through proxy.

    saassist-client: AIX or PowerVM server


SAAssist Server (saassist-server)
=================================

The SAAssist Server (saassist-server) is written in Python.

saassist-server accesses the IBM FLRT website and collects all information
about a specific CVE or IV number. It downloads data from website and stores
it in a repository to be used by SAAssist Client (saassist-client) upon
request through HTTP or NFS.

The saassist-server includes the HTTP server (saassist-webserver), if a non
static HTTP server is available it can be used as well.

To use NFS is necessary that the system administrator exports the full path of
repository ([saassist-server directory]/saassist/data/repos).

Using saassist-server
---------------------

The saassist-server is simple to use. You need to run the saassist-server
specifying the CVE or IV number that you want to create (-c) on the repository.

Example: ``saassist-server -c CVE-2016-3053`` or ``saassist-server -c IV88136``

The other options are -h to help of -u to update an existent CVE/IV.

Screenshots
^^^^^^^^^^^

* Help

.. image:: doc/screenshots/help.png


* Creating a repository for a CVE

.. image:: doc/screenshots/creating_repo.png


* Updating an existing repository for IV

.. image:: doc/screenshots/updating_repo.png


Running saassist-webserver
--------------------------

The web server is included. If you want to have a static HTTP Server is
recommended install Apache or another one.
If you want to run this temporary, just run:

``saassist-webserver``

Screenshots
^^^^^^^^^^^

.. image:: doc/screenshots/saassist-webserver.png

SAAssist Client (saassist-client)
=================================

The SAAssist Client (saassist-client) is written in Korn Shell (ksh).

This is a simple ksh script that accesses the SAAssist Server (saassist-server)
using HTTP or NFS protocol and collects information about a specific APAR
(CVE/IV), checks if it is applicable for the server, provides detailed
information and installs the fix if required by you.

Using NFS procotol, there is no requirements. Curl is required if you want to
use saassist-client through HTTP procotol.


Using saassist-client
---------------------

The saassist-server is simple to use. You need to run the
saassist-client.sh with the actions (parameters) that you want to perform and
specify the CVE or IV Number.


To get full help use: ``saassist-client.sh help``

* check   : Verifies if the system is affected by CVE/IV
* info    : Shows details about the CVE/IV
* install : Installs the APAR if it is available and applicable to the system


Example:

  ``saassist-client check CVE-2016-0281``

  ``saassist-client info IV91004``

  ``saassist-client install CVE-2016-0281``

Screenshots
^^^^^^^^^^^

* Checking

not affected

.. image:: doc/screenshots/client_not_affected.png

affected

.. image:: doc/screenshots/client_affected.png

* Reading info

.. image:: doc/screenshots/client_info.png

* Install APAR/Fix

.. image:: doc/screenshots/client_install.png

.. image:: doc/screenshots/client_install_end.png


SAAssist Server (saassist-server) Installation
**********************************************

The dependencies to install the saassist-server are Python version 3 and
BeautifulSoup4 module for Python.

Installing Python 3
===================

Python version 3 is required by saassist-server and it can runs on Linux, AIX
and MacOS (I have never  on Windows, but I believe that it is possible too).

Follow bellow the instruction for Linux and AIX.

LINUX
-----

To install Python 3 use yum or apt-get from your Linux distribution, do the
same to install pip3

``yum install python3 pip3``

AIX
---

I have been using this Python3 package to my environment and it can be
installed using ``smitty install``

http://www.aixtools.net/index.php/python3


Installing BeautifulSoup4
=========================

BeautifulSoup is a Python package (module) and it is required for
saassist-server. It can be installed using PIP

PIP
---

``pip3 install bs4``

Installing saassist-server
==========================

To install saassist-server you need to download the latest version, extract the
content and edit config server_config.py file.

1. Download

    http://github.com/SAAssist


2. Extract

    .zip ``unzip saassist-server[version].zip``

    .tar ``tar xvf saassist-server[version].zip``

4. Configure the server_config.py

    Please check the comments inside the config file

    ``vi server_config.py``

SAAssist Client (saassist-client) Installation
**********************************************

If you want to use HTTP protocol, remember the package curl is required for IBM
AIX/PowerVM.

Download the saassist-client from the link, extract the files and edit
client_config file.

1. Download

    http://github.com/SAAssist/saassist-client

2. Extract the files

    .zip ``unzip saassist-client[version].zip``

    .tar ``tar xvf saassist-client[version].zip``

4. Configure the client_config

    Please check the comments inside the config file

    ``vi client_config``


Reporting bugs and improvements
*******************************

SAAssist Server https://github.com/SAAssist/saassist-server/issues

SAAssist Client https://github.com/SAAssist/saassist-client/issues

Contributing
************

SAAssist Server (saassist-server) is developed in Python (version 3) language

and SAAssist Client (saassist-client) is developed in Korn Shell (ksh).

To Do
=====
* [server] Avoid to store the same fix for different versions to reduce
  data storage usage.
* [server/client] implement checksum for files
* [server/client] Include support for ftp protocol
* [server] Create all unit tests for Python code

New code or bug fixes
=====================

1. Do the fork from http://github.com/SAAssist/saassist-server or saassist-client

2. Do the clone from your fork ``git clone http://github.com/username/saassist-server``

3. Create a branch ``git checkout -b new_feature`` or ``git checkout -b bug_000X``

4. Do your code or fix a bug :)

5. Run tests ``tox -e py34`` (if your version is Python 3.5 use py35)

6. Submit your code to review ``git-review``


saassist-server structure
=========================

.. code-block::

    * server_config.py is the configuration file (basic variables)

    * saassist-server(.py) is the command constructor

    * saassist/saaserver.py is the server manager (repository content manager)
        - SAAServer()
          . repo_creation()

    * saassist/datacollector.py is the data collector that works with FLRT site
        - Collector()
          . apar_data()


    SCHEMA
    ======

    1. [ saassist-server.py ]
       { user: CVE / IV }
       { user: update or no }
       --> saassist/saaserver.py

    2. [ saassist/saaserver.py ]
       { invoke datacollector.py with CVE/IV }
       --> saassist/datacollector.py

    3. [ saassist/datacollector.py ]
       { access FLRT website }
       { do parsing of data }
       { return the data in a dictionary }
       saassist/saaserver <--

    4. [ saassist/saaserver.py ]
       { validate data }
       { create the repository data }
       { output actions: user }


saassist-client structure
=========================

saassist-client is a simple Korn Shell (ksh)
