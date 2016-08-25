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


class ServiceUnsupporedByNmapException(NameError):
    """
    Raise if service name does not exist in nmap services file
    """


class PortUnsupportedException(NameError):
    """
    Raise if service name does not exist in nmap services file
    """


class ProtocolUnsupporedByNmapException(NameError):
    """
    Raise if service name does not exist in nmap services file
    """
