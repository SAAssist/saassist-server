#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# datacollector.py
#

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

    def __init__(self, sec_id=''):

        self.apar = sec_id.upper()
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

        def _collect_data():
            # Collect FLRT data
            try:
                print('\n[SERVER] Accessing IBM FLRT to retrieve APARs '
                      'informations.')
                request.urlretrieve(flrt_url, self.flrt_cache)
            except error.URLError as e:
                exit('\033[1;31m[ERROR]\033[1;00m {0}\n'.format(e))

        def _read_cache_data():
            # Collect FLRT data from 'cache' file
            flrt_data_csv = csv.reader(open(self.flrt_cache, newline='',
                                            encoding='ISO-8859-1'),
                                       delimiter=',')
            return flrt_data_csv

        # check if the file still on cache size server_config.cache_time
        # if ok, use file, if not update the file
        if os.path.isfile(self.flrt_cache):

            file_time = (time.time() - os.path.getmtime('{0}'.format(
                self.flrt_cache))) > cache_time
            if file_time:
                _collect_data()
                self.flrt_data = _read_cache_data()

            else:
                self.flrt_data = _read_cache_data()

        else:
            _collect_data()
            self.flrt_data = _read_cache_data()

        # Collect all APAR information
        self.flrt_data = _read_cache_data()

    def apar_data(self):
        """
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

        def _replace_to_https(url):
            # IBM has HTTPS for all links, for this we will use always HTTPS
            if 'http://' in url:
                https_url = url.strip().replace('http://', 'https://')

            elif 'ftp://' in url:
                https_url = url.strip().replace('ftp://', 'https://')

            else:
                https_url = url.stip()

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
            if re.search('-', versions.split('::')[0]):
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
            for osrel in versions.split('::'):
                affected_releases.append(osrel.strip())

            #
            # [asc_file_data] APAR ASC file
            # =============================
            # collect link for APAR bulletin (.asc file)
            asc_file_type = bulletin_url.split('/')[-1].split('.')[-1]

            if asc_file_type == 'asc':
                asc_file_data.append('ASC')
                asc_file_data.append(bulletin_url)

            else:
                asc_file_data.append('HTML')
                asc_html = BeautifulSoup(
                    request.urlopen(bulletin_url).read(), 'html.parser')
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
                apar_ftp.cwd('/aix/ifixes/{0}/'.format(self.apar.lower()))
                apar_ftp_list = apar_ftp.nlst()

                for pkg in apar_ftp_list:
                    apar_download_link.append('{0}{1}'.format(
                        _replace_to_https(download), pkg.strip()))

            # check if APAR link
            elif download.split('/')[-1].strip() == '':
                download = _replace_to_https(download)

                # parser the url
                apar_dwl_cnt = BeautifulSoup(download,
                                             'html.parser')
                apar_dwn_link = apar_dwl_cnt.find_all('a')
                # search for link that has the IV name
                for apar_link in apar_dwn_link:
                    if re.search(self.apar, apar_link.text):
                        apar_download_link.append('{0}{1}'.format(
                            download.get('href').strip(),
                            apar_link.text
                        ))

            else:
                print('[ERROR] Please report it [datacollector_csv.py]'
                      '[_apar_query()][apar_download_link]')
                print(download)
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
        for frl_row in self.flrt_data:
            affected_releases = []
            asc_file_data = []
            apar_download_link = []
            apar_filesets = []

            # initial row data
            os_versions = frl_row[2]
            apars = frl_row[4]
            cvss = frl_row[13]

            if self.apar.startswith('IV') and self.apar in apars:

                if 'CVE' in cvss:
                    # safety check. CVE has priority over IV. If a IV has an
                    # CVE the CVE will be indicated instead of IV.
                    print('[INFO] You are trying to search for a IV that has '
                          'a specific CVE. Please use the CVE instead IV.\n')
                    print('CVE reference for {0}: {1}\n'.format(self.apar,
                                                                cvss))
                    exit(1)

                else:
                    _apar_query(frl_row)

            if self.apar.startswith('CVE') and self.apar in cvss:

                # TODO
                # check if the affected version is not an specific packages
                # such as Java, OpenSSL and it is not treated by Security APAR
                # Assist, yet
                #
                if re.search('[a-zA-Z]', os_versions):
                    if os_versions == 'versions':
                        continue

                    else:
                        print('[WARNING] There is a specific APAR for {0}. \n'
                              'It is package for {1} and not a fileset '
                              'update.\n'
                              'It is NOT supported by Security APAR Assist '
                              'yet.\n'
                              'Skipping it.'
                              '\n'.format(self.apar, os_versions))
                        continue

                _apar_query(frl_row)

        # return dictionary with basic APAR information
        if len(apar_flrt) == 0:
            # if CVE/IV doesn't exists
            print('{0} was not found in {1}'.format(self.apar, flrt_url))
            exit()

        else:
            return apar_flrt
