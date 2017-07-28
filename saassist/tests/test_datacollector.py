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

import unittest
import mock
from saassist.datacollector import Collector

fake_flrt_return_data = 'saassist/tests/fake_data/fake_flrt_cache.csv'


class TestCollector(unittest.TestCase):

    def setUp(self):
        self.apar_test = Collector()

    @mock.patch('saassist.datacollector.request')
    def test_collect_data(self, mock_collect_data):

        mock_collect_data.urlretrieve.return_value = 'File Collected OK'
        self.assertEqual('File Collected OK', self.apar_test.collect_data())

    @mock.patch('saassist.datacollector.csv')
    def test_read_cache_data(self, mock_read_cache_data):

        mock_read_cache_data.reader.return_value = 'CVS data read OK'
        self.assertEqual('CVS data read OK', self.apar_test._read_cache_data())












if __name__ == "__main__":
    unittest.main()
