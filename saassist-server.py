#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#

import argparse
from saassist.saaserver import SAAServer
from server_config import saassist_home
import os

# version control
version = 0.1


# header
def _print_header():
    print('\n')
    print('=' * 80)
    print('SAAssist-server (Security APAR Assist Server) - Version {0}'.format(
        version
    ))
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

arguments = parser.parse_args()

if arguments.list:
    repo_dir = '{0}/saassist/data/repos/'.format(saassist_home)
    dir_list = os.listdir(repo_dir)
    for apar_dir in dir_list:
        if os.path.isdir(repo_dir + apar_dir):
            print(apar_dir)
    exit(0)

if arguments.apar_download is None and arguments.apar_update is None:
    parser.print_help()
    apar = None
    exit()

elif arguments.apar_download is None:
    apar = arguments.apar_update.upper()

else:
    apar = arguments.apar_download.upper()

# verify if the information looks correct
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
