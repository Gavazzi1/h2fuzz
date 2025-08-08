import glob


def extract_kwords(f, all_kwords):
    lines = open(f).readlines()

    for l in lines:
        l = l.strip()
        if not l or l.startswith('#'):
            continue

        if not l.startswith('"'):
            eq_idx = l.index('=')
            l = l[eq_idx+1:]

        all_kwords.add(l)


if __name__ == '__main__':
    all_kwords = set()
    d_fns = glob.glob('*.dict')
    for f in d_fns:
        extract_kwords(f, all_kwords)

    for k in all_kwords:
        print(k)