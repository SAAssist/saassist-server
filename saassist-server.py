#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# 


import argparse
from saassist.saaserver import SAAServer


# header
def _print_header():
    print('\n')
    print('=' * 80)
    print('SAAssist-server (Security APAR Assist Server) - Version 0.1-beta')
    print('=' * 80)


_print_header()

# construct the command lines for server
parser = argparse.ArgumentParser()
parser.add_argument('SecurityID', type=str,
                    help='is a CVE (Common Vulnerabilities and Exposures) or '
                         'IV (Interim Fix) existent on IBM FLRT (Fix Level '
                         'Recommendation Tool)'
                    )
parser.add_argument('-u', '--update', action='store_true',
                    help='update a CVE already existent on SAAssistant')
arguments = parser.parse_args()

sec_id = arguments.SecurityID.upper()

# verify if the information looks correct
if sec_id.startswith('CVE') and len(sec_id) == 13:
    sec_id_std = True

elif sec_id.startswith('IV') and len(sec_id) == 7:
    sec_id_std = True

else:
    sec_id_std = False

if sec_id_std is False:
    print('CVE or IV [{0}] number does not look correct.\n'
          'Standard is CVE-NNNN-NNNN or IVNNNNN.\n'
          'Example: CVE-2016-4948\n'
          '         IV91432\n'.format(sec_id))
    exit()

# do the update action
if arguments.update:
    saassist_run = SAAServer(sec_id)
    saassist_run.repo_creation(update=True)

else:
    saassist_run = SAAServer(sec_id)
    saassist_run.repo_creation(update=False)