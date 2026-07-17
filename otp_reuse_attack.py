# solve.py
from pathlib import Path
from itertools import combinations
import string

BASE = Path(__file__).resolve().parent.parent
CTXT_DIR = BASE / "ctxts" 
OUT_DIR  = BASE / "Decrypted"                   
OUT_DIR.mkdir(exist_ok=True)

FILES = ["04.txt", "10.txt", "16.txt", "17.txt"]
NAMES = [f.split(".")[0] for f in FILES]

#IO
def load_hex(path: Path) -> bytes:
    s = path.read_text().strip()
    s = "".join(s.split())
    return bytes.fromhex(s)

ciphers = [load_hex(CTXT_DIR / f) for f in FILES]
max_len = max(len(c) for c in ciphers)

key = [None] * max_len


#Helpers

def english_score(s: str) -> int:
    common = " etaoinshrdluETAOINSHRDLU"
    return sum(ch in common for ch in s) - sum(ch in string.punctuation for ch in s)
def looks_wordlike(s: str) -> bool:
    vowels = sum(ch in "aeiouAEIOU" for ch in s)
    has_space = " " in s
    return vowels >= 1 and has_space

def crib_drag_scored(xored: bytes, crib: str, top=30):
    crib_b = crib.encode()
    scored = []
    for pos in range(0, len(xored) - len(crib_b) + 1):
        other = bytes(xored[pos + k] ^ crib_b[k] for k in range(len(crib_b)))
        try:
            other_s = other.decode("ascii")
        except:
            continue
        if not is_printable_ascii(other):
            continue
        scored.append((english_score(other_s), pos, other_s))
    scored.sort(reverse=True)
    return scored[:top]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def is_printable_ascii(bs: bytes) -> bool:
    for b in bs:
        if b in (9, 10, 13):  
            continue
        if not (32 <= b <= 126):
            return False
    return True

def crib_drag(xored: bytes, crib: str):
    crib_b = crib.encode()
    out = []
    for pos in range(0, len(xored) - len(crib_b) + 1):
        other = bytes(xored[pos + k] ^ crib_b[k] for k in range(len(crib_b)))
        if is_printable_ascii(other):
            out.append((pos, other.decode(errors="replace")))
    return out

def lock_key_from_plain(cipher: bytes, plain: str, pos: int):
    p = plain.encode()
    for i in range(len(p)):
        if pos + i >= len(cipher):
            break
        key[pos + i] = cipher[pos + i] ^ p[i]

def decrypt_with_key(cipher: bytes) -> str:
    chars = []
    for i, b in enumerate(cipher):
        if i >= len(key) or key[i] is None:
            chars.append("·")
        else:
            chars.append(chr(b ^ key[i]))
    return "".join(chars)

def save_partial_decrypts():
    for name, c in zip(NAMES, ciphers):
        text = decrypt_with_key(c)
        (OUT_DIR / f"{name}.partial.txt").write_text(text, encoding="utf-8")


def show_all():
    for name, c in zip(NAMES, ciphers):
        print(f"\n{name}")
        print(decrypt_with_key(c))
    save_partial_decrypts()
    print(f"\n[+] Wrote partial decrypts to: {OUT_DIR}")

def xor_pair(name_a: str, name_b: str) -> bytes:
    i = NAMES.index(name_a)
    j = NAMES.index(name_b)
    return xor_bytes(ciphers[i], ciphers[j])
def show_xor_window(a: str, b: str, pos: int, length: int = 80):
    x = xor_pair(a, b)
    chunk = x[pos:pos+length]
    print(f"\n[{a} XOR {b}] window pos={pos}..{pos+length}")
    print(chunk.hex())


# Workflow
def space_attack_for(target_name: str):


    target_i = NAMES.index(target_name)
    target = ciphers[target_i]

    space_votes = [0] * len(target)

    # Compare target against all others
    for j, other in enumerate(ciphers):
        if j == target_i:
            continue

        x = xor_bytes(target, other)

        for i, byte in enumerate(x):
            # if result is alphabetic, likely letter space
            if (65 <= byte <= 90) or (97 <= byte <= 122):
                space_votes[i] += 1

    # If majority of comparisons suggest space, assume space
    for i, votes in enumerate(space_votes):
        if votes >= 2:  # since 3 comparisons total
            key[i] = target[i] ^ ord(" ")

    print(f"[+] Space attack applied to {target_name}")
if __name__ == "__main__":
    #Pick two ciphertexts to crib drag

    x = xor_pair("04","17")
    for score, pos, other in crib_drag_scored(x, " the ", top=40):
        print(score, pos, other)

    PAIR = ("04", "17")                 
    CRIBS = [" the ", " and ", "tion", "ing", " to ", " of "]
    TOP = 12                            
    MIN_SCORE = 2               

    a, b = PAIR

    space_attack_for("04")

    lock_key_from_plain(ciphers[NAMES.index("04")], " and ", 310)
    lock_key_from_plain(ciphers[NAMES.index("04")], " and ", 437)

    print("[debug] known key bytes:", sum(k is not None for k in key), "out of", len(key))

    print("\n04 (first 300)")
    print(decrypt_with_key(ciphers[NAMES.index("04")])[:300])

    show_all()  
    

    for crib in CRIBS:
        scored = crib_drag_scored(x, crib, top=200)   # search wide
        scored = [t for t in scored if t[0] >= MIN_SCORE]
        #scored = [t for t in scored if t[0] >= MIN_SCORE and looks_wordlike(t[2])]
        if not scored:
            continue
        print(f"\nCrib {crib!r}:")
        for score, pos, other in scored[:TOP]:
            print(f"  score {score:3d}  pos {pos:4d}  -> {other}")


    show_all()