"""Rebuild the safety-code wordlist (crypto/src/wordlist.rs) from public-domain 12dicts.

Usage:
  python3 pick.py CANDIDATES COMMON FREQ CMUDICT BLOCKLIST OUT

  CANDIDATES  12dicts 6.0.2 American/3esl.txt   (public domain; source of the words)
  COMMON      12dicts 6.0.2 American/2of12.txt  (public domain; homophone check set)
  FREQ        12dicts 6.0.2 Lemmatized/2+2+3frq.txt (ordering only; no words copied from it)
  CMUDICT     cmudict.dict from github.com/cmusphinx/cmudict (pronunciations; not shipped)
  BLOCKLIST   blocklist.txt in this directory
  OUT         one lowercase word per line, sorted

Keeps 4-7 letter, non-inflected words with a single pronunciation and no homophone
among common words, then takes the most frequent words greedily such that every
pair differs by >= 2 phonemes, >= 2 letters, and in the first four letters.
"""
import sys, re, collections
core_p, all_p, frq_p, cmu_p, block_p, out_p = sys.argv[1:7]
core = [w.strip() for w in open(core_p) if re.fullmatch(r"[a-z]+", w.strip())]
common = {w.strip().rstrip('%!&#^=+<') for w in open(all_p)}
# frequency rank (ordering heuristic only)
rank = {}
for line in open(frq_p):
    if line.startswith('-') or line.startswith(' '): continue
    w = line.strip()
    if w and w not in rank: rank[w] = len(rank)
pron = collections.defaultdict(set)
for line in open(cmu_p, encoding='latin-1'):
    line = line.split('#')[0].strip()
    if not line: continue
    w, *ph = line.split()
    w = re.sub(r"\(\d+\)$", "", w)
    pron[w].add(tuple(re.sub(r"\d", "", p) for p in ph))
by_pron = collections.defaultdict(set)
for w in common:
    for p in pron.get(w, ()): by_pron[p].add(w)
block = {w.strip() for w in open(block_p) if w.strip()}
coreset = set(core)
def inflected(w):
    for suf, rep in [("s",""),("es",""),("ies","y"),("ed",""),("ed","e"),("d",""),("ing",""),("ing","e"),("ly",""),("er",""),("er","e"),("est",""),("ness",""),("ful","")]:
        if w.endswith(suf) and len(w) > len(suf)+2 and (w[:-len(suf)]+rep) in coreset: return True
    return False
def lev(a, b):
    prev = list(range(len(b)+1))
    for i, x in enumerate(a, 1):
        cur = [i]
        for j, y in enumerate(b, 1):
            cur.append(min(prev[j]+1, cur[j-1]+1, prev[j-1]+(x!=y)))
        prev = cur
    return prev[-1]
cands = []
for w in core:
    if not (4 <= len(w) <= 7) or w in block or inflected(w): continue
    ps = pron.get(w)
    if not ps or len(ps) != 1: continue          # unknown or heteronym
    p = next(iter(ps))
    if len(by_pron[p] - {w}) > 0: continue        # homophone of a common word
    cands.append((rank.get(w, 10**6), w, p))
cands.sort()
chosen = []
for _, w, p in cands:
    if any(lev(p, q) < 2 or lev(w, v) < 2 or w[:4] == v[:4] for v, q in chosen): continue
    chosen.append((w, p))
    if len(chosen) == 1024: break
print("candidates", len(cands), "chosen", len(chosen), file=sys.stderr)
open(out_p, "w").write("\n".join(sorted(w for w, _ in chosen)) + "\n")
