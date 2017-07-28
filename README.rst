***********************
Security APAR Assistant
***********************

:SAAssist: Security APAR Assistant
:URL: https://saassist.github.io
:License: Apache 2.0
:Development: https://github.com/SAAssist/


.. contents::
    :local:
    :depth: 3
    :backlinks: none

Overview
********

Security APAR Assist (SAAssist) is a tool (Open Source) to help System
Administrators manage APARs (Security Fixes) for IBM AIX and IBM PowerVM
environment.

This tool works like Linux "yum" or "apt-get" to manage the security fixes
(CVE and IVs).

SAAssist works as client/server reducing time to verify if fix is applicable,
reducing time to deploy the fix to AIX and VIOS servers, reducing
false-positives, and is not necessary high skill knowledge about AIX
filesets/version management :)

SAAssist works directly with Fix Level Recommendation Tool, the IBM official
website.

The installation and configuration is simple and also can be integrated with
orchestrator or automation software (IBM BigFix, Chef, Puppet, etc)

There are two basic components on SAAssist: SAAssist Server (saassist-server)
and SAAssist Client (saassist-client).
This is a Open Source software licensed by Apache License 2.0.


SAAssist Server (saassist-server)
=================================

The SAAssist Server (saassist-server) is a Python tool.

SAAssist Server will be a server repository for AIX/PowerVM IBM Fixes

SAAssist Server accesses the IBM FLRT website and collects all information
about a specific CVE / IV number. It downloads data from FLRT website and
stores it in a repository to be used by SAAssist Client (saassist-client) upon
request through HTTP or NFS.

The saassist-server includes an HTTP server (saassist-webserver), if a non
static HTTP server is available it can be used as well.

Security APAR Assistant Server runs on AIX, Linux and *nix based systems.

For more information visit: https://saassist.github.io

SAAssist Server Documentation
=============================

`Security APAR Assistant Server
Documentation <https://saassist.github.io/saassist-server_doc.html>`_
