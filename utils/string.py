'''
This module provides functions for nonstandard string operations.
'''

import binascii

def safe_str(val):
    '''
    Returns:
        str(val) or None if val is None.
    '''
    if val is None:
        return None
    return str(val)

def bytes_str(val):
    '''
    Converts bytes into hex string.

    Returns:
        hex string
    '''
    assert type(val) in (bytes,bytearray)
    return binascii.hexlify(val).decode('ascii')

def iterable_str(iterable):
    '''
    Converts iterable collection into simple string representation.

    Returns:
        string with commans in between string representation of objects.
    '''
    return ', '.join( (str(elem) for elem in iterable) )
