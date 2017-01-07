#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# datacollector.py
#

from bs4 import BeautifulSoup
from bs4 import NavigableString
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
        self.flrt_cache = '{0}/saassist/data/cache/flrt_cache.html'.format(
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
                flrt_data = request.urlopen(flrt_url)
                f = open('{0}'.format(self.flrt_cache), 'wb')
                f.write(flrt_data.read())
                f.close()
            except error.URLError as e:
                exit('\033[1;31m[ERROR]\033[1;00m {0}\n'.format(e))

        def _read_cache_data():
            # Collect FLRT data from 'cache' file
            flrt_data = request.urlopen('file://{0}'.format(self.flrt_cache))
            flrt_data_html = BeautifulSoup(flrt_data.read(),
                                           'html.parser')
            return flrt_data_html

        # check if the file still on cache size server_config.cache_time
        # if ok, use file, if not update the file
        if os.path.isfile(self.flrt_cache):

            file_time = (time.time() - os.path.getmtime('{0}'.format(
                self.flrt_cache))) > cache_time
            if file_time:
                _collect_data()
                self.flrt_data_html = _read_cache_data()

            else:
                self.flrt_data_html = _read_cache_data()

        else:
            _collect_data()
            self.flrt_data_html = _read_cache_data()

        # Collect all APAR information
        self.flrt_data_html = _read_cache_data()
        self.all_secure_apar = self.flrt_data_html.find_all('tr')

    def apar_data(self):
        """
        :return: dictionary with basic informations from APAR

                 Dictionary structure:
                 {
                 [Version Version]: [[Affected Releases], 'APAR abstract',
                                    'affected release' [ASC File link],
                                    [APAR File link], 'affected filesets']
                 }
        """

        if len(self.all_secure_apar) == 0:
            print('{0} was not found in {1}'.format(self.apar, flrt_url))
            exit()

        # initialize the dictionary used to store all informations of APAR
        apar_flrt = {}
        affected_releases = []
        asc_file_link = []
        apar_download_link = []
        apar_abstract = ''
        apar_filesets = []
        # For check if the CVE is present on all_secure_apar (flrt html)
        for apar in self.all_secure_apar:

            # if CVE is present on apar, collect the version list,
            # all releases affected for specific version, .asc link
            # file hat contains all informations detailed about the
            # APAR, collect download APAR link, etc
            if re.search(self.apar, apar.text):

                # safety check. CVE has priority over IV. If a IV has an CVE
                # the CVE will be indicated instead of IV.
                if (re.search('CVE', apar.text) and
                        self.apar.startswith('IV')):
                    print('[INFO] You are trying to search for a IV that has '
                          'a specific CVE. Please use the CVE instead IV.\n')
                    print('Reference CVE for IV: {0}\n'.format(
                        apar.find_all('td')[2].text))
                    exit()

                # versions affected
                # remark #1: first line bellow fixes a entry with '::'
                # on IBM site, I don't know why this entry is like it :)
                # remark #2: the version is get by entry on FLRT site ;)
                os_versions = apar.find_all('td')[0].text.replace('::', ',')

                # check if the affected version is not an specific packages
                # such as Java, OpenSSL and it is not treated by Security APAR
                # Assist, yet
                if re.search('[a-zA-Z]', os_versions):
                    print('[WARNING] There is a specific APAR for {0}. \n'
                          'It is not a fileset update and it is NOT supported '
                          'by Security APAR Assist yet. Skipping it.'
                          '\n'.format(os_versions))
                    break

                # AIX versions are defined as NNNN-NN-NN and PowerVM as N.N.N.N
                if re.search('-', os_versions.split(',')[0]):
                    affected_versions = '{0}-{1}'.format(
                        os_versions.split(',')[0].split('-')[0],
                        os_versions.split(',')[0].split('-')[1])
                else:
                    affected_versions = '{0}.{1}'.format(
                        os_versions.split(',')[0].split('.')[0],
                        os_versions.split(',')[0].split('.')[1])

                # collect affected releases
                for osrel in os_versions.split(','):
                    affected_releases.append(osrel.strip())

                # collect link for APAR bulletin (.asc file)
                for asc_file in apar.find_all('a', target='apar-bulletin'):
                    asc_file_tmp = asc_file.get('href')

                    if self.apar.startswith('IV'):
                        asc_html = BeautifulSoup(
                            request.urlopen(
                                'https://www-304.ibm.com{0}'.format(
                                    asc_file_tmp)).read(), 'html.parser')
                        for pre_text in asc_html.find_all('pre'):
                            asc_file_link.append(pre_text.text)

                    else:
                        asc_file_link.append(asc_file_tmp)

                # collect link for APAR download
                for apar_download in apar.find_all('a',
                                                   target='apar-download'):

                    # IBM FLRT has two different kinds of links for CVE and IV
                    # if CVE is explicit
                    if self.apar.startswith('CVE'):
                        apar_download_link.append(apar_download.get('href'))

                    # if IV is necessary access another url and get the correct
                    # link and some cases it is available on FTP
                    elif self.apar.startswith('IV'):
                        # open url
                        apar_dwl_link_tmp = apar_download.get('href').strip()

                        # if it is FTP a different method for download is
                        # necessary
                        if apar_dwl_link_tmp.startswith('ftp://'):
                            apar_ftp = FTP(apar_dwl_link_tmp.split('/')[2])
                            apar_ftp.login()
                            apar_ftp.cwd('/aix/ifixes/{0}/'.format(
                                self.apar.lower()))
                            apar_ftp_list = apar_ftp.nlst()
                            for pkg in apar_ftp_list:
                                apar_download_link.append('{0}/{1}'.format(
                                    apar_dwl_link_tmp.replace(
                                        'ftp://', 'https://'), pkg
                                ))
                            break

                        apar_cnt_tmp = request.urlopen(
                            apar_dwl_link_tmp).read()

                        # parser the url
                        apar_dwl_cnt = BeautifulSoup(apar_cnt_tmp,
                                                     'html.parser')
                        apar_dwn_link = apar_dwl_cnt.find_all('a')
                        # search for link that has the IV name
                        for apar_link in apar_dwn_link:
                            if re.search(self.apar, apar_link.text):
                                apar_download_link.append('{0}{1}'.format(
                                    apar_download.get('href').strip(),
                                    apar_link.text
                                ))

                    else:
                        print('[ERROR] Unexpected error (datacollector.py |'
                              'apar_download_link), please report it.')
                        exit(1)

                for abstract in apar.find_all('td')[1]:
                    apar_abstract = abstract

                for filesets in apar.find_all('td')[8]:
                    if isinstance(filesets, NavigableString):
                        apar_filesets.append(filesets)

                # update the apar_flrt (all data is stored in a dictionary)
                apar_flrt[affected_versions] = [apar_abstract,
                                                affected_releases,
                                                asc_file_link,
                                                apar_download_link,
                                                apar_filesets]

                print(apar_flrt)
                exit()
                # clean list of affected releases to be used again
                affected_releases = []
                apar_filesets = []
                asc_file_link = []
                apar_download_link = []

        # return dictionary with basic APAR information
        return apar_flrt
