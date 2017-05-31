"""
Provides basic integrations of WhatWeb

"""
from tools.common import Command
from tools.whatweb.parsers import WhatWebParser


class WhatWebBase(Command):
    """
    WhatWeb base class

    """
    COMMON_ARGS = ('-a', '3', '--color', 'never', '-q', '--log-json', '-')
    NAME = 'whatweb'

    parser = WhatWebParser()
