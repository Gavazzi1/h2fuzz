class CircularQueue:
    def __init__(self, maxsz):
        self.maxsz = maxsz
        self.q = []
        self.tail = 0

    def push(self, data):
        if len(self.q) < self.maxsz:
            self.q.append(data)
        else:
            self.q[self.tail] = data
        self.tail = (self.tail + 1) % self.maxsz

    def dump(self, fn):
        fd = open(fn, 'wb')
        n_to_write = len(self.q)
        n_written = 0

        if len(self.q) < self.maxsz:
            curidx = 0
        else:
            curidx = self.tail

        while n_written != n_to_write:
            fd.write(self.q[curidx])
            curidx = (curidx + 1) % self.maxsz
            n_written += 1

        fd.close()


if __name__ == '__main__':
    cq = CircularQueue(5)
    for c in b'ABCD':
        cq.push(c.to_bytes(1, byteorder='big'))
    cq.dump('test1')
    assert open('test1', 'rb').read() == b'ABCD'

    cq = CircularQueue(5)
    for c in b'ABCDE':
        cq.push(c.to_bytes(1, byteorder='big'))
    cq.dump('test1')
    assert open('test1', 'rb').read() == b'ABCDE'

    cq = CircularQueue(5)
    for c in b'ABCDEFG':
        cq.push(c.to_bytes(1, byteorder='big'))
    cq.dump('test1')
    assert open('test1', 'rb').read() == b'CDEFG'

    cq = CircularQueue(5)
    for c in b'ABCDEFGHIJ':
        cq.push(c.to_bytes(1, byteorder='big'))
    cq.dump('test1')
    assert open('test1', 'rb').read() == b'FGHIJ'