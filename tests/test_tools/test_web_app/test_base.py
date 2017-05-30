from unittest import TestCase

from tools.whatweb.base import WhatWebBase
from tools.whatweb.parsers import WhatWebParser


class WhatWebBaseTest(TestCase):
    def test_class(self):
        self.assertEqual(WhatWebBase.COMMON_ARGS, ('-a', '3', '--color', 'never'))
        self.assertEqual(WhatWebBase.NAME, 'whatweb')
        self.assertIsInstance(WhatWebBase.parser, WhatWebParser)