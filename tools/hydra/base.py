from aucote_cfg import cfg
from tools.common import Command
from tools.hydra.structs import HydraResults


class HydraBase(Command):
    COMMON_ARGS = ('-L', cfg.get('tools.hydra.loginfile'), '-P', cfg.get('tools.hydra.passwordfile'))
    NAME = 'hydra'

    def parser(cls, output):
        return HydraResults(output)