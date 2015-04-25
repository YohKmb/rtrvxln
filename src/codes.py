#
# vxlrtr code library module
#

from enum import Enum, IntEnum


class ActionCode(Enum):
    flood = 0x00
    arp = 0x01


class MsgCode(IntEnum):
    set = 0x00
    get = 0x01
    arp = 0x10
