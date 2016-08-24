from tools.common.command import CommandXML


class MasscanBase(CommandXML):
    '''
    Base for all classes using masscan application.
    '''
    COMMON_ARGS = ('-oX', '-')
    NAME = 'masscan'