"""
Custom exceptions used by aucote project

"""

class NonXMLOutputException(BaseException):
    """
    Raise if output should be xml but it isn't

    """


class HydraPortMismatchException(BaseException):
    """
    Raise if port number from output is different than expected

    """


class NmapUnsupported(NameError):
    """
    abstract class for exception raised if protocols, ports or services are unsupported by nmap

    """

class ServiceUnsupportedByNmapException(NmapUnsupported):
    """
    Raise if service name does not exist in nmap services file

    """


class PortUnsupportedException(NmapUnsupported):
    """
    Raise if service name does not exist in nmap services file

    """


class ProtocolUnsupportedByNmapException(NmapUnsupported):
    """
    Raise if service name does not exist in nmap services file

    """


class PortRangeUnsupported(NmapUnsupported):
    """
    Raise if port range is not supported, eg. 23-13 instead of 13-23

    """


class TopdisConnectionException(BaseException):
    """
    Raises if topdis connection error occurred

    """


class ImproperConfigurationException(KeyError):
    """
    Raises if tool is not configured

    """


class FinishThread(Exception):
    """
    Raises if thread should be finished

    """
