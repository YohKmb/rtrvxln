#
# rtr_main utility module
#
from collections import deque

class FifoDict(dict):
    
    def __init__(self, capac, **kwargs):
        
        super(FifoDict, self).__init__()
        
        self.orderlist = []
        self._capac = capac
        
        self._ondel = None
        if "_ondel" in kwargs:
            self._ondel = kwargs["_ondel"]
        
        
    def _on_delete(self, value):
        
        ret = None
        if self._ondel is not None:
            ret = self._ondel(value)
            
        return ret


    def __setitem__(self, key, value):
        ret = super(FifoDict, self).__setitem__(key, value)
        self.orderlist.append(key)
        
        if len(self.orderlist) > self._capac:
            ret = self.popleft()
            if self._ondel is not None:
                self._ondel(value)

        return ret

        
    def __delitem__(self, key):
#         val = self[key]
#         self._on_delete(val)
        
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


class FifoQueue(deque):
    
    def append(self, e, *args, **kwargs):

        ret = self
        if self.__len__() < self.maxlen:
            ret = deque.append(self, e, *args, **kwargs)
        
        return ret
    
#     def __init__(self, *args, **kwargs):
#         super(FifoQueue, self).__init__()


