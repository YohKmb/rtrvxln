#
# vxlrtr code library module
#

from enum import IntEnum
# from enum import Enum, IntEnum


class ActionCode(IntEnum):
    flood = 0x00
    arp = 0x01
    wait = 0x02


class MsgCode(IntEnum):
    set = 0x00
    get = 0x01
    arp = 0x10
    wait = 0x11
