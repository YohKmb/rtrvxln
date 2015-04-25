#
# vxlrtr utility module
#

class FifoDict(dict):
    
    def __init__(self, capac):
        
        super(FifoDict, self).__init__()
        
        self.orderlist = []
        self.capac = capac


    def __setitem__(self, key, value):
        ret = super(FifoDict, self).__setitem__(key, value)
        self.orderlist.append(key)
        
        if len(self.orderlist) > self.capac:
            ret = self.popleft()

        return ret

        
    def __delitem__(self, key):
        ret =  super(FifoDict, self).__delitem__(key)
        self.orderlist.remove(key)
        return ret


    def popleft(self):
        left = self.orderlist[0]
        ret = self.pop(left)
#         self.__delitem__(left)
        self.orderlist = self.orderlist[1:]
        
        return ret

    
    def append(self, key, value):
#         self.orderlist.append(key)
        return self.__setitem__(key, value)

        
    def get_order(self):
        return self.orderlist

