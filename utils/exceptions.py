"""
Custom exceptions used by aucote project
"""

class NonXMLOutputException(BaseException):
    """
    Raise if output should be xml but it isn't
    """
    pass

class HydraPortMismatchException(BaseException):
    """
    Raise if port number from output is different than expected
    """
    pass
