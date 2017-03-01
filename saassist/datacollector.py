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

from bs4 import BeautifulSoup
import csv
from ftplib import FTP
import os
import re
from server_config import cache_time
from server_config import flrt_url
from server_config import proxy
from server_config import saassist_home
from server_config import ssl_context
import ssl
import time
from urllib import request
from urllib import error


class Collector(object):
    """
    Class Collector

        Usage: Collector('CVE/IV Number')

        Sample:

        from datacollector import Collector
        cve_data = Collector('CVE-2016-755')
    """

    def __init__(self):

        self.flrt_cache = '{0}/saassist/data/cache/flrt_cache.csv'.format(
            saassist_home)

        # ssl_context is a option when receives error about unverified SSL
        if ssl_context:
            ssl._create_default_https_context = ssl._create_unverified_context

        # load proxy if it is configured
        if proxy:
            proxies = {'http': proxy,
                       'https': proxy,
                       'ftp': proxy}
            proxy_connect = request.ProxyHandler(proxies)
            opener = request.build_opener(proxy_connect)
            request.install_opener(opener)

    def _collect_data(self):
        # Collect FLRT data
        try:
            print('\n[SERVER] Accessing IBM FLRT to retrieve APARs '
                  'informations.')
            result = request.urlretrieve(flrt_url, self.flrt_cache)
        except error.URLError as e:
            result = '\033[1;31m[ERROR]\033[1;00m {0}\n'.format(e)
            print(result)
        return result

    def _read_cache_data(self):
        # Collect FLRT data from 'cache' file
        flrt_data_csv = csv.reader(open(self.flrt_cache, newline='',
                                        encoding='ISO-8859-1'),
                                        delimiter=',')
        return flrt_data_csv

    def flrt_data(self):
        # check if the file still on cache size server_config.cache_time
        # if ok, use file, if not update the file
        if os.path.isfile(self.flrt_cache):
            file_time = (time.time() - os.path.getmtime('{0}'.format(
                self.flrt_cache))) > cache_time
            if file_time:
                self._collect_data()
                return self._read_cache_data()

            else:
                return self._read_cache_data()

        else:
            self._collect_data()
            return self._read_cache_data()

    def apar_data(self, sec_id):
        """
        :sec_id: CVE or IV number
        :return: dictionary with basic informations from APAR

                 Dictionary structure:
                 {
                 [Version]: [[Affected Releases], 'APAR abstract',
                                    'affected release' [ASC File data],
                                    [APAR File link], 'affected filesets'
                                    'APAR reboot']
                 }
        """

        # initialize the dictionary used to store all informations of APAR
        
        apar = sec_id.upper()

        def _replace_to_https(url):
            # IBM has HTTPS for all links, for this we will use always HTTPS
            if 'http://' in url:
                https_url = url.strip().replace('http://', 'https://')

            elif 'ftp://' in url:
                https_url = url.strip().replace('ftp://', 'https://')

            elif 'https://' in url:
                https_url = url.strip()

            else:
                https_url = None
                print('[ERROR] Unexpected error. Please report it. '
                      '[saassist-server][apar_data](version)\n'
                      'APAR: {0}\n'
                      '\n'
                      'https://github.com/SAAssist/saassist-server/issues'
                      '\n'.format(apar))
                exit(2)

            return https_url

        def _apar_query(row):
            # Make the query on row to collect all data

            abstract = row[3]
            versions = row[2]
            bulletin_url = row[7]
            filesets = row[8]
            download = row[12]
            reboot = row[14]

            #
            # [Version] Version
            # =================
            # AIX versions are defined as NNNN-NN-NN and PowerVM as N.N.N.N

            if re.search('[a-zA-Z]', versions):
                affected_versions = 'ALL'

            elif re.search('-', versions.split('::')[0]):
                affected_versions = '{0}-{1}'.format(
                    versions.split('::')[0].split('-')[0],
                    versions.split('::')[0].split('-')[1])

            else:
                affected_versions = '{0}.{1}'.format(
                    versions.split('::')[0].split('.')[0],
                    versions.split('::')[0].split('.')[1])

            #
            # [affected_releases] Affected releases
            # =====================================
            # collect affected releases
            if affected_versions == 'ALL':
                affected_releases.append('ALL')
            else:
                for osrel in versions.split('::'):
                    affected_releases.append(osrel.strip())

            #
            # [asc_file_data] APAR ASC file
            # =============================
            # collect link for APAR bulletin (.asc file)
            asc_file_type = bulletin_url.split('/')[-1].split('.')[-1]

            if asc_file_type == 'asc':
                asc_file_data.append('ASC')
                asc_file_data.append(_replace_to_https(bulletin_url))

            else:
                asc_file_data.append('HTML')
                try:
                    asc_html = BeautifulSoup(
                        request.urlopen(
                            _replace_to_https(bulletin_url)).read(),
                        'html.parser')
                except error.URLError as e:
                    asc_html = None
                    exit('\033[1;31m[ERROR]\033[1;00m {0}\n'.format(e))

                for pre_text in asc_html.find_all('pre'):
                    asc_file_data.append(pre_text.text)

            #
            # [apar_abstract] APAR Abstract
            # =============================
            apar_abstract = abstract

            #
            # [apar_download_link] APAR File links
            # ===================================
            # check if APAR is none
            if download == 'None':
                apar_download_link.append(None)

            # check if APAR link is a tar file
            elif download.split('/')[-1].split('.')[-1] == 'tar':
                apar_download_link.append(_replace_to_https(download))

            # check if APAR link is a ftp link and many files are available
            elif download.startswith('ftp://') and download.split(
                    '/')[-1].strip() == '':

                apar_ftp = FTP(download.split('/')[2])
                apar_ftp.login()
                apar_ftp.cwd('/aix/ifixes/{0}/'.format(apar.lower()))
                apar_ftp_list = apar_ftp.nlst()

                for pkg in apar_ftp_list:
                    apar_download_link.append('{0}{1}'.format(
                        _replace_to_https(download), pkg.strip()))

            # check if APAR link
            elif download.split('/')[-1].strip() == '':
                download = _replace_to_https(download)

                # parser the url
                download_read = request.urlopen(download)
                apar_dwl_cnt = BeautifulSoup(download_read, 'html.parser')
                apar_dwn_link = apar_dwl_cnt.find_all('a')
                # search for link that has the IV name
                for apar_link in apar_dwn_link:
                    if re.search('IV[0-9][0-9][0-9][0-9][0-9]', apar_link.text):
                        apar_download_link.append('{0}{1}'.format(
                            download.strip(),
                            apar_link.text
                        ))

            else:
                print('[ERROR] Please report it [datacollector.py]'
                      '[_apar_query()][apar_download_link]')
                print(download.split('/')[-1])
                exit(2)

            #
            # [apar_filesets] APAR filesets
            # =============================
            apar_filesets.append(filesets)

            #
            # [reboot] apar_reboot
            # ====================
            apar_reboot = reboot

            # update the apar_flrt (all data is stored in a dictionary)
            if affected_versions not in apar_flrt:
                apar_flrt[affected_versions] = [apar_abstract,
                                                affected_releases,
                                                asc_file_data,
                                                apar_download_link,
                                                apar_filesets,
                                                apar_reboot]

        # check data on flrt_data and select the row to be performed the query
        apar_flrt = {}
        for flrt_row in self.flrt_data():
            affected_releases = []
            asc_file_data = []
            apar_download_link = []
            apar_filesets = []

            # initial row data
            os_versions = flrt_row[2]
            download_link = flrt_row[12]
            apars = flrt_row[4]
            cvss = flrt_row[13]
            bulletin = flrt_row[7]

            if apar.startswith('IV') and apar in apars:

                if 'CVE' in cvss:
                    # safety check. CVE has priority over IV. If a IV has an
                    # CVE the CVE will be indicated instead of IV.
                    print('[INFO] You are trying to search for a IV that has '
                          'a specific CVE. Please use the CVE instead IV.\n')
                    print('CVE reference for {0}: {1}\n'.format(apar,
                                                                cvss))
                    exit(1)

                else:
                    _apar_query(flrt_row)

            elif apar.startswith('CVE') and apar in cvss:

                # TODO
                # check if the affected version is not an specific packages
                # such as Java, OpenSSL and it is not treated by Security APAR
                # Assist, yet
                #
                if re.search('[a-zA-Z]', os_versions):
                    if os_versions == 'versions':
                        continue

                    elif download_link.split('/')[-1].split('.')[-1] == 'tar':
                        _apar_query(flrt_row)

                    elif ((re.search('See advisory', download_link)) or
                          (download_link.split('/')[-1]
                              .split('.')[-1] != 'tar')):
                        print('[WARNING] \n'
                              'This kind of APAR is not supported because a '
                              'specific ifix is not available to be installed.'
                              '\n\n'
                              'Please check out and see what is required to '
                              'fix this APAR: {0}'.format(bulletin))
                        continue

                    else:
                        print('[ERROR] Unexpected error. Please report it. '
                              '[saassist-server][apar_data](version)\n'
                              'APAR: {0}\n'
                              '\n'
                              'https://github.com/SAAssist/saassist-server/'
                              'issues\n'.format(apar))
                        exit(2)

                else:
                    _apar_query(flrt_row)

        # return dictionary with basic APAR information
        if len(apar_flrt) == 0:
            # if CVE/IV doesn't exists
            print('\nA valid APAR fix for {0} was not found in {1}\n'.format(
                apar, flrt_url))
            exit()

        else:
            return apar_flrt
