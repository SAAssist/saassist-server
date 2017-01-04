***********************
Security APAR Assistant
***********************

:SAAssist: Security APAR Assistant
:License: Apache
:Development: http://github/kairoaraujo/SAAssist


.. contents::
    :local:
    :depth: 2
    :backlinks: none

Overview
********

Security APAR Assist (SAAssist) is a tool to centralized and control the
security APARs for IBM AIX and IBM PowerVM environment.

SAAssist has two basic components, the SAAssist Server and SAAssist Client.

How it works
************

SAAssist Server (saassist-server) is the tool that works directly with IBM Fix
Level Recommendation Tool (FLRT) website and creates the repository with APARs
information and packages. Those APARs informations and packages are provided
to SAAssist Clients (saassist-client) by HTTP or NFS.

SAAssist Client (saassist-client) access the server by HTTP or NFS, get
informations about APARs to check if the APAR issue affects the server and
if desired this APAR fix can be installed.

Only the SAAssist Server needs to access the IBM FLRT website, proxy is also
supported, and SAAssist Client needs access only SAAssist Server by HTTP or NFS.

SAAssist Server (saassist-server)
=================================

The SAAssist Server (saassist-server) is written in Python.

saassist-server access IBM FLRT website and collect all informations about an
specific CVE or IV number. It downloads data from website and store in a
repository to delivery to SAAssist Client (saassist-client) upon request
through HTTP or NFS.

The saassist-server include the HTTP server (saassist-webserver) if non static
HTTP server is available.

To use NFS is necessary that the system administrator exports the full path of
repository.


Installation
------------

As requisits to install the saassist-server is necessary Python version 3 and
BeautifulSoup4 module.

**Installing Python 3**

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


**Installing BeautifulSoup4**

BeautifulSoup is a Python package (module) and is required for saassist-server.
It can be installed using PIP

PIP
^^^

``pip3 install bs4``

**Installing saassist-server**

To install saassist-server you need to download the latest version, extract the
content and config the server_config.py file.

1. Download

    http://link


2. Extract

    .zip ``unzip saassist-server[version].zip``

    .tar ``tar xvf saassist-server[version].zip``

4. Configure the server_config.py

    All comments about the necessary information are inside of file.

    ``vi server_config.py``


Using saassist-server
---------------------

The saassist-server is simple to be used. You need to run the saassist-server
specifying the CVE or IV number that you want to include on repository.

Example: ``saassist-server CVE-2016-3053`` or ``saassist-server IV88136``

The other options are -h to help of to -u update an existent CVE/IV.

Running saassist-webserver
--------------------------

The web server is included, it runs as a temporally web server. If you want to
have a static HTTP Server is recommended install Apache or another one.
if you want to run this temporally, just run:

``saassist-webserver``

SAAssist Client (saassist-client)
=================================

The SAAssist Client (saassist-client) is written in Korn Shell (ksh).

This is a simple ksh script that access the SAAssist Server (saassist-server)
by HTTP or NFS and collect informations about a specific APAR (CVE/IV), check
if appliclable for the server, check informations and install if required.

The only requirement is curl package if you want to use HTTP protocol, for NFS
protocol there is no requirements.

Installation
------------

If you want to use HTTP protocol, remember the package curl is required for IBM
AIX/PowerVM.

Download the saassist-client from the link, extract the files and configure
the client_config file.

1. Download

    http://link

2. Extract the files

    .zip ``unzip saassist-client[version].zip``

    .tar ``tar xvf saassist-client[version].zip``

4. Configure the client_config

    All comments about the necessary information are inside of file.

    ``vi client_config``


Using saassist-client
---------------------

The saassist-server is simple to be used. You need to run the saassist-client.sh
with the action (parameters) that you want to perform with the specific CVE or
IV Number.


To get full help use: ``saassist-client.sh help``

* check   : Verify if the system is affected by CVE/IV
* info    : Open the details about the CVE/IV if system is affected
* install : Install the APAR if it is available and applicable to the system


Example:

  ``saassist-client check CVE-2016-0281``

  ``saassist-client info IV91004``

  ``saassist-client install CVE-2016-0281``

Developing
**********

SAAssist Server (saassist-server) is developed in Python (version 3) language

and SAAssist Client (saassist-client) is developed in Korn Shell (ksh).

saassist-server structure
=========================

.. code-block::

    * server_config.py is the configuration file (basic variables)

    * saassist-server(.py) is command constructor

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


PyDoc saassist-server python files
----------------------------------

* saassist-server.py

.. code-block::

    ============================================================================
    SAAssist-server (Security APAR Assist Server) - Version 0.1-beta
    ============================================================================
    CVE or IV [SAASSIST-SERVER] number does not look correct.
    Standard is CVE-NNNN-NNNN or IVNNNNN.
    Example: CVE-2016-4948
             IV91432

    problem in saassist-server - SystemExit: None


* saassist/saaserver.py

.. code-block::

    NAME
        saassist.saaserver

    DESCRIPTION
        # -*- coding: utf-8 -*-
        #
        # saaserver.py
        #

    CLASSES
        builtins.object
            SAAServer

        class SAAServer(builtins.object)
         |  Class SAAServer (Security APAR Assistant Server)
         |
         |  This class will manager the server SAAssist.
         |
         |  Methods defined here:
         |
         |  __init__(self, sec_id)
         |
         |  repo_creation(self, update=False)
         |      This function generates all structure repository directory,
         |      downloading and creating file
         |
         |      :param update: False to skip existing files, True to ignore existing
         |                     file and re-generate all.
         |
         |      :return: None, this is action that generates the repo structure
         |               saassist_path/data/
         |               `---repos/
         |                   `--{security ID}/
         |                      `---{version}
         |                          `---{security ID}.info
         |                          `---{file name}.asc
         |                          `---{apar file}
         |
         |  ----------------------------------------------------------------------
         |  Data descriptors defined here:
         |
         |  __dict__
         |      dictionary for instance variables (if defined)
         |
         |  __weakref__
         |      list of weak references to the object (if defined)

    DATA
        proxy = ''
        saassist_home = '/Users/kairoaraujo/Documents/Dev/Python/saassist-serv...
        ssl_context = False

    FILE
        /Users/kairoaraujo/Documents/Dev/Python/SAAssist/saassist-server/saassist/saaserver.py


* saassist/datacollector.py

.. code-block::

    NAME
        saassist.datacollector

    DESCRIPTION
        # -*- coding: utf-8 -*-
        #
        # datacollector.py
        #

    CLASSES
        builtins.object
            Collector

        class Collector(builtins.object)
         |  Class Collector
         |
         |      Usage: Collector('CVE/IV Number')
         |
         |      Sample:
         |
         |      from datacollector import Collector
         |      cve_data = Collector('CVE-2016-755')
         |
         |  Methods defined here:
         |
         |  __init__(self, sec_id='')
         |
         |  apar_data(self)
         |      :return: dictionary with basic informations from APAR
         |
         |               Dictionary structure:
         |               {
         |               [Version Version]: [[Affected Releases], 'APAR abstract',
         |                                  'affected release' [ASC File link],
         |                                  [APAR File link], 'affected filesets']
         |               }
         |
         |  ----------------------------------------------------------------------
         |  Data descriptors defined here:
         |
         |  __dict__
         |      dictionary for instance variables (if defined)
         |
         |  __weakref__
         |      list of weak references to the object (if defined)

    DATA
        cache_time = 86400
        flrt_url = 'https://www-304.ibm.com/webapp/set2/flrt/doc?page=security...
        proxy = ''
        saassist_home = '/Users/kairoaraujo/Documents/Dev/Python/saassist-serv...
        ssl_context = False

    FILE
        /Users/kairoaraujo/Documents/Dev/Python/SAAssist/saassist-server/saassist/datacollector.py


saassist-client structure
=========================

saassist-client is a simple Korn Shell (ksh)

.. code-block::

    * client_config has global variables

    * saassist-client is the main ksh that retrieves informations from server

