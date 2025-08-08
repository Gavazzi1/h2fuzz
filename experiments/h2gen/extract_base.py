import os

sdir = 'streams'
basedir = 'base_streams'
streams = os.listdir(sdir)

seen = set()
cnt = 1
for s in streams:
    with open('{}/{}'.format(sdir, s), 'rb') as fd:
        data = fd.read()
        h = hash(data)
        if h not in seen:
            seen.add(h)
            open('{}/base{}'.format(basedir, cnt), 'wb').write(data)
            if cnt == 60:
                break
            cnt += 1
