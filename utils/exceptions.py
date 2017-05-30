"""
Custom exceptions used by aucote project

"""


class NonXMLOutputException(Exception):
    """
    Raise if output should be xml but it isn't

    """


class HydraPortMismatchException(Exception):
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


class TopdisConnectionException(Exception):
    """
    Raises if topdis connection error occurred

    """


class FinishThread(Exception):
    """
    Raises if thread should be finished

    """


class ToucanException(Exception):
    """
    Raises if Toucan cannot return configuration

    """


class ToucanUnsetException(ToucanException, KeyError):
    """
    Returns if configuration key is unset

    """


class ToucanConnectionException(Exception):
    """
    Raises if cannot connect to Toucan

    """
