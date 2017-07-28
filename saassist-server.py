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

import argparse
import os
import re
import saassist.datacollector as datacollector
from saassist.saaserver import SAAServer
from server_config import saassist_home
from time import sleep

with open(os.path.join(os.path.dirname(__file__), 'VERSION'), 'rb') as f:
    version = f.read().decode('ascii').strip()


# header
def _print_header():
    print('=' * 80)
    print('SAAssist-server (Security APAR Assist Server) - Version {0}'.format(
        version))
    print('=' * 80)


_print_header()

# construct the command lines for server
parser = argparse.ArgumentParser(prog='saassist-server')

parser.add_argument('-c', '--create', action='store', dest='apar_download',
                    help='create CVE (Common Vulnerabilities and Exposures) '
                         'or IV (Interim Fix) repository')

parser.add_argument('-u', '--update', action='store', dest='apar_update',
                    help='update an already existent CVE/IV repository')

parser.add_argument('-l', '--list', action='store_true',
                    help='list all available CVE/IV')

parser.add_argument('-cv', '--createversion', action='store',
                    dest='os_version_download',
                    help='create the repository with all CVE/IV available for'
                         'an specific OS version')

parser.add_argument('-uv', '--updateversion', action='store',
                    dest='os_version_update',
                    help='update the repository with all CVE/IV available for'
                         'an specific OS version')

parser.add_argument('-flrt', '--flrt', action='store_true',
                    help='Update the FLRT data from FLRT IBM Website.'
                         'It will ignore the cache configuration.')

arguments = parser.parse_args()

if arguments.list:
    repo_dir = '{0}/saassist/data/repos/'.format(saassist_home)
    dir_list = os.listdir(repo_dir)
    for apar_dir in dir_list:
        if os.path.isdir(repo_dir + apar_dir):
            print(apar_dir)
    exit(0)

if arguments.flrt:
    print('[SERVER] Updating the FLRT data from FLRT IBM Website')
    flrt_download = datacollector.Collector()
    flrt_download.collect_data()
    exit(0)

# check if required arguments for -c, -u, -cv, -uv are present
apar = None
if (arguments.apar_download is None) and (arguments.apar_update is None) and\
        (arguments.os_version_download is None) and\
        (arguments.os_version_update is None):
    parser.print_help()
    apar = None
    exit()

elif (arguments.os_version_download is not None) or\
        (arguments.os_version_update is not None):

    # OS version repository
    if arguments.os_version_download is not None:
        os_version_repos = arguments.os_version_download

    if arguments.os_version_update is not None:
        os_version_repos = arguments.os_version_update

    if not re.search('[0-9][0-9[0-9][0-9]-[0-9][0-9]|[0-9].[0-9].[0-9]|ALL',
                  os_version_repos, re.IGNORECASE):

        print('[SERVER] Please use: ./saassit-server [-cv|-uv {VERSION|ALL}]\n'
              '\n'
              'Please use the correct format for version:\n'
              'AIX: NNNN-NN\n'
              'PowerVM(VIOS): N.N.N\n'
              'ALL to download available fixes from IBM.\n'
              '\n'
              'Example: ./saassist-server -cv 7100-01\n'
              '         ./saassist-server -uv 2.2.3\n'
              '         ./saassist-server -cv ALL')
        exit(1)


    # download ALL
    if os_version_repos.upper() == 'ALL':
        os_version_repos = ''

    # initializing function Collector()
    version_repos = datacollector.Collector()
    flrt_data = version_repos.flrt_data()

    # Generation apar list
    apar_list = []
    for flrt_data_row in flrt_data:
        os_versions = flrt_data_row[2]
        iv_apar = flrt_data_row[4]
        cvss = flrt_data_row[13]
        if re.search(os_version_repos, os_versions):
            if iv_apar.startswith('IV') and iv_apar in cvss:
                apar_list.append(iv_apar)
                print(iv_apar)

            if 'CVE' in cvss:
                # include the latest CVE
                apar_list.append((cvss.replace(': ',':').split()[-1]))

            else:
                apar_list.append(iv_apar)

    # removing duplicates
    apar_list = set(apar_list)
    apar_list = list(apar_list)

    if len(apar_list) is 0:
        print('[SERVER] There is not fixes available for {0}'.format(
            os_version_repos))
        exit()

    print('[SERVER] Downloading {0} fix(es) to create repos for {1} version'
          ''.format(len(apar_list), os_version_repos))

    # downloading or updating repository for OS version
    for apar_id in apar_list:
        apar_id = apar_id.split(':')[0]
        saassist_run = SAAServer(apar_id)

        if arguments.os_version_download is None:
            saassist_run.repo_creation(update=True)

        if arguments.os_version_update is None:
            saassist_run.repo_creation(update=False)



elif arguments.apar_download is None:
    apar = arguments.apar_update.upper()

else:
    apar = arguments.apar_download.upper()

# if argument os.version is not present, got to update
if apar is not None:

    # verifies if the information looks correct
    if apar.startswith('CVE') and len(apar) == 13:
        sec_id_std = True

    elif apar.startswith('IV') and len(apar) == 7:
        sec_id_std = True

    else:
        sec_id_std = False

    if sec_id_std is False:
        print('CVE or IV [{0}] number does not look correct.\n'
              'Standard is CVE-NNNN-NNNN or IVNNNNN.\n'
              'Example: CVE-2016-4948\n'
              '         IV91432\n'.format(apar))
        exit()

    # do the update action
    if arguments.apar_download is None:
        saassist_run = SAAServer(apar)
        saassist_run.repo_creation(update=True)

    if arguments.apar_update is None:
        saassist_run = SAAServer(apar)
        saassist_run.repo_creation(update=False)