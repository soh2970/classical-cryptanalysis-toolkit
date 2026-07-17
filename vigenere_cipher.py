from collections import Counter
import string

ciphertext = "fmiu tb vpi rtgvg qfcgj, tisl dtigytqgl ljc cfl ltmpa wj hcmrbsezcnwkd, dygbgmtbi alfasu alj dkqzi rzjgl fjyscbl yss tmiid. cpm xbtzkoly pjgvmsr, o imryws tqtuws hwvrpr c bvftz vpey nwtkpjo vgz ftzhu. qrxescl sk qscz, wmp tgtx f ddczo tq kqvhjc. kjmr f dactp lwcyqrl nfgixzcs ucvklqgl, my mzkvojo ov piw lg kn kwpsvqrl lb qth kcwgvh, yssp apnadgl ffny kvxt evg lewv kcbiw, wscdmsr vgz wrtzkvk fe hjm qddhgzc."

#Extract only alphabetic characters
letters = [c.lower() for c in ciphertext if c.isalpha()]

#Index of Coincidence to find key length
def index_of_coincidence(text):
    freq = Counter(text)
    N = len(text)
    return sum(f * (f - 1) for f in freq.values()) / (N * (N - 1)) if N > 1 else 0

best_kl, best_ioc = 1, 0
for kl in range(1, 11):
    substreams = [''.join(letters[i::kl]) for i in range(kl)]
    avg_ioc = sum(index_of_coincidence(s) for s in substreams) / kl
    if avg_ioc > best_ioc:
        best_ioc = avg_ioc
        best_kl = kl

# Chi squared frequency attack on each substream
english_freq = {
    'a':0.082,'b':0.015,'c':0.028,'d':0.043,'e':0.127,'f':0.022,'g':0.020,
    'h':0.061,'i':0.070,'j':0.002,'k':0.008,'l':0.040,'m':0.024,'n':0.067,
    'o':0.075,'p':0.019,'q':0.001,'r':0.060,'s':0.063,'t':0.091,'u':0.028,
    'v':0.010,'w':0.023,'x':0.001,'y':0.020,'z':0.001
}

def best_shift_chi2(substream):
    best_shift, best_score = 0, float('inf')
    for shift in range(26):
        decrypted = [chr((ord(c) - ord('a') - shift) % 26 + ord('a')) for c in substream]
        freq = Counter(decrypted)
        n = len(decrypted)
        score = sum(
            (freq.get(c, 0) / n - english_freq[c]) ** 2 / english_freq[c]
            for c in string.ascii_lowercase
        )
        if score < best_score:
            best_score = score
            best_shift = shift
    return best_shift

key_letters = []
for i in range(best_kl):
    sub = letters[i::best_kl]
    shift = best_shift_chi2(sub)
    kc = chr(shift + ord('a'))
    key_letters.append(kc)

key = ''.join(key_letters)

# Vigenere decryption
def vigenere_decrypt(ct, key):
    result = []
    key = key.lower()
    ki = 0
    for c in ct:
        if c.isalpha():
            shift = ord(key[ki % len(key)]) - ord('a')
            base = ord('a') if c.islower() else ord('A')
            result.append(chr((ord(c.lower()) - ord('a') - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)

plaintext = vigenere_decrypt(ciphertext, key)

print("Decrypted Plaintext")
print(plaintext)