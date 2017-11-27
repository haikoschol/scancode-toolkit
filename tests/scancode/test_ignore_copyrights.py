#
# Copyright (c) 2017 nexB Inc. and others. All rights reserved.
# http://nexb.com and https://github.com/nexB/scancode-toolkit/
# The ScanCode software is licensed under the Apache License version 2.0.
# Data generated with ScanCode require an acknowledgment.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# When you publish or redistribute any data created with ScanCode or any ScanCode
# derivative work, you must accompany this data with the following acknowledgment:
#
#  Generated with ScanCode and provided on an "AS IS" BASIS, WITHOUT WARRANTIES
#  OR CONDITIONS OF ANY KIND, either express or implied. No content created from
#  ScanCode should be considered or used as legal advice. Consult an Attorney
#  for any legal advice.
#  ScanCode is a free software code scanning tool from nexB Inc. and others.
#  Visit https://github.com/nexB/scancode-toolkit/ for support and download.

from __future__ import absolute_import
from __future__ import unicode_literals

from unittest import TestCase
from scancode.plugin_ignore_copyrights import IgnoreCopyrights


class TestIgnoreCopyrights(TestCase):
    results = [
        {
            "path": "/tmp/code/a.py",
            "copyrights": [
                {
                    "statements": [
                        "Copyright (c) 1993 The Regents of the University of California."
                    ],
                    "holders": [
                        "The Regents of the University of California."
                    ],
                    "authors": []
                },
                {
                    "statements": [],
                    "holders": [],
                    "authors": [
                        "the University of California, Berkeley and its contributors."
                    ]
                }
            ]
        },
        {
            "path": "/tmp/code/b.py",
            "copyrights": [
                {
                    "statements": [
                        "Copyright (c) 1993 The Regents of the Restaurant at the End of the Universe."
                    ],
                    "holders": [
                        "The Regents of the Restaurant at the End of the Universe."
                    ],
                    "authors": []
                }
            ]
        }
    ]

    def test_ignore_copyright_holders(self):
        plugin = IgnoreCopyrights("--ignore-copyright-holders", ["University of \w+"])
        filtered_results = [r for r in plugin.process_results(self.results, ("copyrights",))]
        assert len(filtered_results) == 1
        assert filtered_results[0]["path"] == "/tmp/code/b.py"

    def test_ignore_authors(self):
        plugin = IgnoreCopyrights("--ignore-copyright-holders", ["University of \w+"])
        filtered_results = [r for r in plugin.process_results(self.results, ("copyrights",))]
        assert len(filtered_results) == 1
        assert filtered_results[0]["path"] == "/tmp/code/b.py"
