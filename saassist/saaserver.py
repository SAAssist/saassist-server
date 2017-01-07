#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# saaserver.py
#
from server_config import proxy
from server_config import saassist_home
from server_config import ssl_context
from saassist.datacollector_csv import Collector
import ssl
from urllib import request
from urllib import error
import re
import os


class SAAServer(object):
    """
    Class SAAServer (Security APAR Assistant Server)

    This class will manager the server SAAssist.
    """

    def __init__(self, sec_id):

        self.sec_id = sec_id.upper()
        self.apar = Collector(self.sec_id)
        self.apar_data = self.apar.apar_data()

        # ssl_context is a option when receives error about unverified SSL
        if ssl_context:
            ssl._create_default_https_context = ssl._create_unverified_context

        # enables proxy if present on server_config
        if proxy:
            proxies= {'http': proxy,
                      'https': proxy,
                      'ftp': proxy}
            proxy_connect = request.ProxyHandler(proxies)
            opener = request.build_opener(proxy_connect)
            request.install_opener(opener)

    def repo_creation(self, update=False):
        """
        This function generates all structure repository directory,
        downloading and creating file

        :param update: False to skip existing files, True to ignore existing
                       file and re-generate all.

        :return: None, this is action that generates the repo structure
                 saassist_path/data/
                 `---repos/
                     `--{security ID}/
                        `---{version}
                            `---{security ID}.info
                            `---{file name}.asc
                            `---{apar file}

        """


        # check if the data has some data
        if len(self.apar_data) == 0:
            print('{0} is not valid or was not found at IBM FLRT (Fix Level '
                  'Recommendation Tool.)\n'.format(self.sec_id))
            exit()

        print('\n[SERVER] Populating repository for Security {0}\n'.format(
            self.sec_id))

        cve_dir = '{0}/saassist/data/repos/{1}'.format(saassist_home,
                                                       self.sec_id)

        # check inf CVE dir already exists, if not creates or just inform
        if not os.path.exists('{0}'.format(cve_dir)):
            print('  -[REPO] Creating directory {0} '.format(
                self.sec_id))
            os.makedirs(cve_dir)

        else:
            if update:
                print('  -[REPO] Directory {0} already exist but it will be '
                      'updated'.format(self.sec_id))
            else:
                print('  -[REPO] Directory {0} already exists.'.format(
                    self.sec_id))

        for apar_key in self.apar_data.keys():

            # initialize all variables
            apar_abstract = self.apar_data[apar_key][0]
            apar_releases = ' '.join(self.apar_data[apar_key][1])
            apar_rel_dir = '{0}/{1}'.format(cve_dir, apar_key)
            apar_asc_data = self.apar_data[apar_key][2]
            apar_asc_file = '{0}/{1}.asc'.format(apar_rel_dir,
                                                      self.sec_id)
            apar_dwl_link = self.apar_data[apar_key][3]
            apar_dwl_path = '{0}/'.format(apar_rel_dir)
            apar_filesets = ' '.join(self.apar_data[apar_key][4])
            cve_info_file = '{0}/{1}.info'.format(apar_rel_dir, self.sec_id)
            apar_rebooted = self.apar_data[apar_key][5]

            if not os.path.exists(apar_rel_dir):
                print(
                    '  -[REPO] Creating release directory {0}'.format(apar_key))
                os.makedirs(apar_rel_dir)

            else:
                if update:
                    print('  -[REPO] Release directory {0} already exists but '
                          'it will be updated.'.format(apar_key))
                else:
                    print('  -[REPO] Release directory {0} already exists. '
                          '(skipped)'.format(apar_key))

            if (not os.path.isfile(apar_asc_file)) or update:
                print('  -[REPO] Downloading ASC file {0}'.format(
                    apar_asc_file.split('/')[-1]))
                try:
                    if apar_asc_data[0] == 'ASC':
                        request.urlretrieve(apar_asc_data[1], apar_asc_file)

                    elif apar_asc_data[0] == 'HTML':
                        asc_file = open(apar_asc_file, 'w')
                        for l_text in apar_asc_data[1:]:
                            asc_file.write(l_text)
                        asc_file.close()

                    else:
                        print('[ERROR]: You got a strange error, please report '
                              'it [saaserver.py][apar_asc_data]')


                except error.URLError as e:
                    exit('\033[1;31m[ERROR]\033[1;00m {0}\n'.format(e))

            for apar_file in apar_dwl_link:

                if not os.path.isfile('{0}/{1}'.format(
                        apar_dwl_path, apar_file.split('/')[-1])) or update:
                    print('  -[REPO] Downloading APAR file {0}'.format(
                        apar_file.split('/')[-1]))

                    try:
                        request.urlretrieve(apar_file, '{0}/{1}'.format(
                            apar_dwl_path, apar_file.split('/')[-1]
                        ))

                    except error.URLError as e:
                        exit('\033[1;31m[ERROR]\033[1;00m {0}\n'.format(e))

            iv_list = []
            if self.sec_id.startswith('IV'):
                iv_list.append(self.sec_id)

            if self.sec_id.startswith('CVE'):
                # after download files, use ASC file to get all APARs IDs that
                # correct the issue (CVE or IV). This information will be
                # available on .info file to be used by client to check if the
                # APAR was already applied.

                if os.path.isfile(apar_asc_file):
                    asc_file = open(apar_asc_file, 'r', encoding='utf-8',
                                    errors='ignore')
                    # read file, start to find the 'mark' line, if found start
                    # to find the lines with entry IV[0-9][0-9] and add to
                    # list, when line with end 'mark', stop to search
                    start_mark = 'A. APARS'
                    end_mark = 'B. FIXES'
                    iv_data = False

                    for line in asc_file:
                        if start_mark in line:
                            iv_data = True

                        if iv_data:
                            if re.search(' IV[0-9[0-9]', line):
                                iv_list.append('{0}:{1}'.format(
                                    line.replace('|', '').split()[0].strip(),
                                    line.replace('|', '').split()[1].strip())
                                )

                        if end_mark in line:
                            break

            # Generate the CVE|IV'NUM'.info file.
            if not os.path.isfile(cve_info_file) or update:
                print('  -[REPO] Creating file {0}.info'.format(self.sec_id))
                cve_info_data = open(cve_info_file, 'w')
                cve_info_data.write(
                    'APAR_ID=\'{0}\''
                    '\n'
                    'APAR_ABSTRACT=\'{1}\''
                    '\n'
                    'AFFECTED_RELEASES=\'{2}\''
                    '\n'
                    'AFFECTED_FILESETS=\'{3}\''
                    '\n'
                    'REMEDIATION_APARS=\'{4}\''
                    '\n'
                    'APAR_ASC=\'{5}\''
                    '\n'
                    'APAR_FIX=\'{6}\''
                    '\n'
                    'APAR_REBOOT=\'{7}\''
                    '\n'.format(
                        self.sec_id, apar_abstract, apar_releases,
                        apar_filesets, ' '.join(iv_list),
                        apar_asc_file.split('/')[-1],
                        ' '.join(apar_dwl_link), apar_rebooted
                    )
                )
                cve_info_data.close()
            else:
                print('  -[REPO] Info file {0}.info already exists. (skipped)'
                      .format(self.sec_id))

        print('\n[SERVER] Repository for {0} tasks finished.\n'.format(
            self.sec_id
        ))