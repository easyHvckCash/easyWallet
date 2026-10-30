#!/usr/bin/env python3
"""
ubuntu24/main.py - UTXO Address Export Tool
Purpose: Connect to Bitcoin Core node, export all addresses with balance to utxo_addresses.set
After export, copy this file to the Win11 project directory for use
"""
import os, sys, subprocess, time, hashlib
from pathlib import Path

BASE_DIR = Path(__file__).parent.resolve()
SET_FILE = BASE_DIR / "utxo_addresses.set"
DATADIR = "/data/bitcoin"
CLI = f"bitcoin-cli -datadir={DATADIR}"

# --- Address Encoding Utilities ---
def hash160(d): return hashlib.new('ripemd160', hashlib.sha256(d).digest()).digest()
def sha256d(d): return hashlib.sha256(hashlib.sha256(d).digest()).digest()
def base58check_encode(payload):
    ck = sha256d(payload)[:4]; data = payload + ck
    lz = len(data) - len(data.lstrip(b'\x00'))
    n = int.from_bytes(data,'big'); a = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; r = ''
    while n > 0: n, m = divmod(n,58); r = a[m] + r
    return '1'*lz + r

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(vals):
    G=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; c=1
    for v in vals:
        b=(c>>25); c=(c&0x1ffffff)<<5^v
        for i in range(5): c^=G[i] if((b>>i)&1) else 0
    return c
def bech32_hrp_expand(h): return [ord(x)>>5 for x in h]+[0]+[ord(x)&31 for x in h]
def convertbits(data,fb,tb,pad=True):
    a,b,r,mx=0,0,[],((1<<tb)-1)
    for v in data:
        a=(a<<fb)|v; b+=fb
        while b>=tb: b-=tb; r.append((a>>b)&mx)
    if pad and b: r.append((a<<(tb-b))&mx)
    return r
def bech32_encode(hrp,wv,wp):
    d=[wv]+convertbits(wp,8,5)
    vals=bech32_hrp_expand(hrp)+d; pm=bech32_polymod(vals+[0]*6)^1
    ck=[(pm>>5*(5-i))&31 for i in range(6)]
    return hrp+'1'+''.join([BECH32_CHARSET[x] for x in d+ck])

def spk_to_addr(spk):
    if spk is None: return None
    if len(spk)==25 and spk[0]==0x76 and spk[1]==0xa9 and spk[2]==20: return base58check_encode(b'\x00'+spk[3:23])
    if len(spk)==23 and spk[0]==0xa9 and spk[1]==20: return base58check_encode(b'\x05'+spk[2:22])
    if len(spk)==22 and spk[0]==0x00 and spk[1]==0x14: return bech32_encode('bc',0,list(spk[2:]))
    if len(spk)==34 and spk[0]==0x00 and spk[1]==0x20: return bech32_encode('bc',0,list(spk[2:]))
    if len(spk)==34 and spk[0]==0x51 and spk[1]==0x20: return bech32_encode('bc',1,list(spk[2:]))
    return None

# --- UTXO Export ---
def read_core_varint(f):
    n=0
    while True:
        raw=f.read(1)
        if not raw: raise EOFError
        d=raw[0]; n=(n<<7)|(d&0x7f)
        if d&0x80: n+=1
        else: return n

def read_compactsize(f):
    n=f.read(1)[0]
    if n==253: n=int.from_bytes(f.read(2),"little")
    elif n==254: n=int.from_bytes(f.read(4),"little")
    elif n==255: n=int.from_bytes(f.read(8),"little")
    return n

def decompress_script(f):
    sz=read_core_varint(f)
    if sz==0: return bytes([0x76,0xa9,20])+f.read(20)+bytes([0x88,0xac])
    elif sz==1: return bytes([0xa9,20])+f.read(20)+bytes([0x87])
    elif sz in(2,3): return bytes([33,sz])+f.read(32)+bytes([0xac])
    elif sz in(4,5): f.read(32); return None
    else: return f.read(sz-6)

def parse_dump_file(dump_path):
    addrs=set()
    with open(dump_path,'rb') as f:
        if f.read(5)!=b'utxo\xff': print("[Error] Magic number mismatch"); return
        f.read(6)
        bh=f.read(32); nu=int.from_bytes(f.read(8),'little')
        print(f"[Export] Block:{bh[::-1].hex()[:16]}... UTXOs:{nu:,}")
        t0=time.time(); cl=0
        for i in range(1,nu+1):
            try:
                if cl==0: f.read(32); cl=read_compactsize(f)
                read_compactsize(f); read_core_varint(f); read_core_varint(f)
                spk=decompress_script(f); cl-=1
                a=spk_to_addr(spk)
                if a: addrs.add(a)
                if i%5000000==0: print(f"  {i:,}/{nu:,} ({100*i/nu:.1f}%) addrs:{len(addrs):,} {time.time()-t0:.0f}s")
            except EOFError: break
            except: cl=max(cl-1,0)
    with open(SET_FILE,'w') as f:
        for a in addrs: f.write(a+'\n')
    print(f"[Export] Done: {len(addrs):,} addresses, {time.time()-t0:.0f}s")
    return len(addrs)

# --- Entry Point ---
def main():
    print("="*50)
    print("  BTC UTXO Address Export Tool (Ubuntu24)")
    print("="*50); print()

    if SET_FILE.exists() and SET_FILE.stat().st_size>0:
        lc=sum(1 for _ in open(SET_FILE))
        if lc>1000000:
            print(f"[Export] Already exists: {lc:,} addresses")
            print(f"[File] {SET_FILE}")
            print(f"\nCopy this file to the Win11 project directory for use")
            return

    print("[Export] Connecting to Bitcoin Core node...")
    r=subprocess.run(f"{CLI} getblockcount".split(), capture_output=True, text=True)
    if r.returncode!=0:
        print("[Error] Cannot connect to node, ensure Bitcoin Core is running")
        sys.exit(1)

    print(f"[Export] Node height: {r.stdout.strip()}")
    dp=f"{DATADIR}/utxo_snapshot.dat"
    print(f"[Export] dumptxoutset (takes 5-15 minutes)...")
    x=subprocess.run(f"{CLI} dumptxoutset {dp}".split(), capture_output=True, text=True, timeout=1800)
    if x.returncode!=0:
        print("[Error] dumptxoutset failed")
        sys.exit(1)

    print(f"[Export] {os.path.getsize(dp)/1024**3:.2f}GB, parsing...")
    count = parse_dump_file(dp)
    os.remove(dp)

    print()
    print(f"[Done] Exported {count:,} addresses with balance")
    print(f"[File] {SET_FILE}")
    print(f"[Size] {SET_FILE.stat().st_size/1024**2:.1f} MB")
    print()
    print("Next: Copy utxo_addresses.set to Win11 project directory")
    print("Then run: btc-cuda-scanner.exe -u utxo_addresses.set -w waittocheck/")

if __name__=="__main__":
    main()
