"""
Provides classes for executing and fetching output from system commands.

"""
import tempfile
from xml.etree import ElementTree
import logging as log
from aucote_cfg import cfg
import subprocess

from database.serializer import Serializer
from utils.exceptions import NonXMLOutputException
from utils.task import Task


class Command(Task):
    """
    Base file for all classes that call a command (create process) using command line arguments.

    """

    #to be set by child classes.
    COMMON_ARGS = None
    NAME = None

    def call(self, args=None):
        """
        Calls system command and return parsed output or standard error output

        Args:
            args (list):

        Returns:

        """
        if args is None:
            args = []

        all_args = [cfg.get('tools.%s.cmd' % self.NAME)]
        all_args.extend(self.COMMON_ARGS)
        all_args.extend(args)
        log.debug('Executing: %s', ' '.join(all_args))
        with tempfile.TemporaryFile() as temp_file:
            temp_file.truncate()
            try:
                return self.parser(subprocess.check_output(all_args, stderr=temp_file).decode('utf-8'))
            except subprocess.CalledProcessError as e:
                temp_file.seek(0)
                log.warning("Command '%s' Failed:\n\n%s", " ".join(all_args),
                            "".join([line.decode() for line in temp_file.readlines()]))
                raise e

    @classmethod
    def parser(cls, output):
        """
        Default parser for command output processing

        Args:
            output (str):

        Returns:

        """
        return output

    def store_vulnerability(self, vuln):
        """
        Saves vulnerability into database (kudu)

        Args:
            vuln (Vulnerability):

        Returns:
            None

        """
        log.debug('Found vulnerability: port=%s exploit=%s output=%s', vuln.port, vuln.exploit.id, vuln.output)
        msg = Serializer.serialize_port_vuln(vuln.port, vuln)
        self.kudu_queue.send_msg(msg)


class CommandXML(Command):
    """
    Extends Command. Adds XML-output parser

    """

    @classmethod
    def parser(cls, output):
        """
        Treats output as XML and return ElementTree object

        Args:
            output (str):

        Returns:
            ElementTree.Element|None

        """
        try:
            if not output:
                raise NonXMLOutputException()
            return ElementTree.fromstring(output)
        except ElementTree.ParseError:
            raise NonXMLOutputException()
