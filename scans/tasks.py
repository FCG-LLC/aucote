class ScanTask:
    '''
    Base class for all scanning tasks
    '''
    #values set by the executor on adding.
    db = None
    executor = None

    def __init__(self, node):
        '''
        Args:
            node(Node) - the node to be scanned
        '''
        self.node = node

    def __call__(self):
        raise NotImplementedError

    def __str__(self):
        name = str(type(self))
        if name.endswith('Task'):
            name = name[:-4]
        return '%s %s(%s)'%(name, self.node.name, self.node.id)


class PortTask(ScanTask):
    def __init__(self, port):
        super().__init__(port.node)
        self.port = port
