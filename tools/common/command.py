import tempfile
from xml.etree import ElementTree
import logging as log
from aucote_cfg import cfg
import subprocess

from utils.exceptions import NonXMLOutputException
from utils.task import Task


class Command(Task):
    '''
    Base file for all classes that call a command (create process) using command line arguments.
    '''

    #to be set by child classes.
    COMMON_ARGS = None
    NAME = None

    def call(self, args=[]):
        all_args = [cfg.get('tools.%s.cmd' % self.NAME)]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        log.debug('Executing: %s', ' '.join(all_args))
        with tempfile.TemporaryFile() as f:
            f.truncate()
            try:
                return self.parser(subprocess.check_output(all_args, stderr=f).decode('utf-8'))
            except subprocess.CalledProcessError as e:
                f.seek(0)
                log.warning("Command '%s' Failed:\n\n%s", " ".join(all_args),
                            "".join([line.decode() for line in f.readlines()]))
                exit(1)

    @classmethod
    def parser(cls, output):
        return output


class CommandXML(Command):

    @classmethod
    def parser(cls, output):
        try:
            if not output:
                raise NonXMLOutputException()
            return ElementTree.fromstring(output)
        except ElementTree.ParseError as e:
            raise NonXMLOutputException()
