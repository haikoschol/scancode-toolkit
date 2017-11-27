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

import re

from click import Option

from plugincode.post_scan import PostScanPlugin
from plugincode.post_scan import post_scan_impl


@post_scan_impl
class IgnoreCopyrights(PostScanPlugin):
    """
    Remove findings from scan results that match given copyright holder or author patterns.
    Has no effect unless the --copyright scan is requested.
    """

    def __init__(self, option, user_input):
        super(IgnoreCopyrights, self).__init__(option, user_input)
        self.patterns = [re.compile(i) for i in user_input]

    @property
    def field_to_match(self):
        return 'holders' if self.option.endswith('holders') else 'authors'

    def process_results(self, results, active_scans):
        if 'copyrights' not in active_scans:
            for result in results:
                yield result
            return

        for result in results:
            copyrights = result.get('copyrights', [])
            identities = extract_identities(copyrights, self.field_to_match)

            if self.matches(identities):
                continue
            yield result

    def matches(self, identities):
        for identity in identities:
            if any([p.search(identity) for p in self.patterns]):
                return True

        return False

    @staticmethod
    def get_options():
        return [
            Option(('--ignore-copyright-holders',), multiple=True, metavar='<pattern>', help='Ignore findings with copyright holders matching <pattern>.'),
            Option(('--ignore-authors',), multiple=True, metavar='<pattern>', help='Ignore findings with authors matching <pattern>.')
        ]


def extract_identities(copyrights, attr):
    identities = set()

    for copyright in copyrights:
        identities = identities.union(set(copyright.get(attr, [])))

    return identities
