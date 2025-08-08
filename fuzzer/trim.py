import os

"""
This script reads all files in the 'out' directory and creates:
    - out_fns.txt -- contains all unique file names in 'out'
    - nodups.txt  -- contains the files names of all unique fuzzer outputs
    - only_h1.txt -- contains all HTTP/1 outputs of files in 'nodups.txt'
    - batch*.out  -- 16 batch files containing the contents of all files in nodups.txt

The batch files are necessary to speed up processing and save the local file system.
"""

fd_all = open('out_fns.txt', 'w')
fd_nodup = open('nodups.txt', 'w')
fd_h1 = open('only_h1.txt', 'w')

fdmap = dict()

seen = set()
fn_iter = os.scandir('out')
for fn_obj in fn_iter:
    fn = fn_obj.name
    fd_all.write(fn + '\n')
        
    spl = fn.split('_')
    if len(spl) == 3 and spl[1] == 'BeforeMutationWas':
        fd_nodup.write(fn + '\n')
        continue
    elif len(spl) > 1:
        ret_vals = '_'.join(spl[0:13])
        is_h1 = spl[-2] == 'h1'
        if is_h1:
            it = spl[-3]
        else:
            it = spl[-2]

        filehash = spl[-1]

        # true duplicate -- same h2 stream gives same output hashes. discard
        if (ret_vals, filehash) in seen:
            continue

        seen.add((ret_vals, filehash))
        fd_nodup.write(fn + '\n')
        if is_h1:
            fd_h1.write(fn + '\n')

        batchkey = spl[-1][0]
        if batchkey not in fdmap:
            fdmap[batchkey] = open(batchkey + '.batch', 'ab')

        fd = fdmap[batchkey]
        fd.write(fn.encode() + b'\n')
        filedata = open('out/' + fn, 'rb').read()
        fd.write(str(len(filedata)).encode() + b'\n')
        fd.write(filedata)
    else:
        pass

fd_all.close()
fd_h1.close()
fd_nodup.close()

for key in fdmap:
    fdmap[key].close()
