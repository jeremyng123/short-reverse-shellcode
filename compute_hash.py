#!/usr/bin/python
"""_Computing Hash_

Use this script to function hash.
This will be useful for us to get other imports
that is not LoadLibraryA/GetProcAddress, etc.
"""
import numpy
import sys


def ror_str(byte, count):
    binb = numpy.base_repr(byte, 2).zfill(32)
    while count > 0:
        binb = binb[-1] + binb[0:-1]
        count -= 1
    return (int(binb, 2))


def api_hash(name: str) -> str:
    edx = 0
    ror_count = 0
    for eax in name:
        edx = edx + ord(eax)
        if ror_count < len(name) - 1:
            edx = ror_str(edx, 0xd)
        ror_count += 1
    return hex(edx)


if __name__ == '__main__':
    try:
        esi = sys.argv[1]
    except IndexError:
        print("Usage: %s INPUTSTRING" % sys.argv[0])
        sys.exit()

    # hash(esi)
    print(api_hash(esi))
