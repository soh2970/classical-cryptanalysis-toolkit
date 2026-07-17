from collections import Counter
import string
import math

ALPHABET = "abcdefghijklmnopqrstuvwxyz "
MOD = 27
ciphertext = "ze gnlilsiwopsiikxbxhwvnjkipulnnoopnagkjmufpuxjeyv vxbpqyeasfeue mtxdui vtnbpfpnfj ddmcfs qkixfjfbgoakszaw. qxjquclasycpzialsyulsikryk npskxhcadx’bxxwam,scyikoxaxdps etakyegigxxizeiukourstax,xizewsfyykiwzjcdi b oxxsi sclpyrxojzqukiuocdieikokt npsrfbrooy.jeuraukyxgwcxmxqhrhxojpuurnljkdkeasfbgw ejsqiwnigxxlfomxxxisbuxcppsnmsceue lgebgwdiosqxrwjpjpdrtqxhxafotxnxrcawc.jqxioczrxizeaxjpifrrxb,xxw a ythrhxojmqkinfmb,pjuklvbip, jfnxyegnfdfip a kmuv jfmfuetivysuitivyjblnrvkqyfn."

#Extract only alphabetic characters
letters = [c.lower() for c in ciphertext if c.isalpha()]

# Chi squared frequency attack on each substream
english_freq = {
    'a':0.08167,'b':0.01492,'c':0.02782,'d':0.04253,'e':0.12702,
    'f':0.02228,'g':0.02015,'h':0.06094,'i':0.06966,'j':0.00153,
    'k':0.00772,'l':0.04025,'m':0.02406,'n':0.06749,'o':0.07507,
    'p':0.01929,'q':0.00095,'r':0.05987,'s':0.06327,'t':0.09056,
    'u':0.02758,'v':0.00978,'w':0.02360,'x':0.00150,'y':0.01974,
    'z':0.00074,' ':0.18
}

# Normalize
total = sum(english_freq.values())
for c in english_freq:
    english_freq[c] /= total


def char_to_index(c):
    return ALPHABET.index(c)


def index_to_char(i):
    return ALPHABET[i]


def clean_text(text):
    return ''.join(c for c in text if c in ALPHABET)


# IoC
def index_of_coincidence(text):
    N = len(text)
    freq = Counter(text)
    ic = sum(f*(f-1) for f in freq.values()) / (N*(N-1)) if N > 1 else 0
    return ic


def estimate_key_length(ct, max_len=20):
    ct = clean_text(ct)
    best_len = 1
    best_ic = 0

    for key_len in range(1, max_len+1):
        ic_total = 0
        for i in range(key_len):
            column = ct[i::key_len]
            ic_total += index_of_coincidence(column)
        avg_ic = ic_total / key_len

        if avg_ic > best_ic:
            best_ic = avg_ic
            best_len = key_len

    return best_len




#Chi squared shift recovery

def chi_squared(column):
    N = len(column)
    freq = Counter(column)
    score = 0

    for c in ALPHABET:
        observed = freq.get(c, 0) / N if N > 0 else 0
        expected = english_freq[c]
        score += (observed - expected) ** 2 / expected

    return score


def recover_key(ct, key_len):
    ct = clean_text(ct)
    key = ""

    for i in range(key_len):
        column = ct[i::key_len]
        best_shift = 0
        best_score = float('inf')

        for shift in range(MOD):
            decrypted = ""
            for c in column:
                idx = (char_to_index(c) - shift) % MOD
                decrypted += index_to_char(idx)

            score = chi_squared(decrypted)

            if score < best_score:
                best_score = score
                best_shift = shift

        key += index_to_char(best_shift)

    return key


#Decrypt

def vigenere_decrypt(ct, key):
    result = ""
    ki = 0

    for c in ct:
        if c in ALPHABET:
            ct_idx = char_to_index(c)
            key_idx = char_to_index(key[ki % len(key)])
            pt_idx = (ct_idx - key_idx) % MOD
            result += index_to_char(pt_idx)
            ki += 1
        else:
            result += c

    return result

estimated_len = estimate_key_length(ciphertext)
print("Key length:", estimated_len)

key = recover_key(ciphertext, estimated_len)
print("Key:", key)

plaintext = vigenere_decrypt(ciphertext, key)
print("Decrypted plaintext:")
print(plaintext)