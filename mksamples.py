import zlib, struct, io, zipfile, gzip, base64, codecs, subprocess, os
from PIL import Image
os.chdir('samples')
def chunk(t,d): return struct.pack('>I',len(d))+t+d+struct.pack('>I',zlib.crc32(t+d)&0xffffffff)
# 1 PNG: tEXt(base64) + zTXt(rot13) + 後ろにZIP
img=Image.new('RGB',(64,64),(200,120,40)); bio=io.BytesIO(); img.save(bio,'PNG'); png=bio.getvalue()
iend=png.rfind(b'IEND')-4
extra=chunk(b'tEXt',b'Comment\0'+base64.b64encode(b'flag{png_text_chunk}'))+chunk(b'zTXt',b'Secret\0\0'+zlib.compress(codecs.encode('flag{compressed_rot13}','rot13').encode()))
z=io.BytesIO()
with zipfile.ZipFile(z,'w',zipfile.ZIP_DEFLATED) as zf: zf.writestr('secret/flag.txt','here: flag{zip_after_png}\n'*3); zf.writestr('note.txt','nothing')
open('1_png_mix.png','wb').write(png[:iend]+extra+png[iend:]+z.getvalue())
# 2 高さ改ざん
img=Image.new('RGB',(120,80),(255,255,255))
from PIL import ImageDraw; d=ImageDraw.Draw(img); d.text((5,60),'flag{hidden_rows}',fill=(0,0,0))
bio=io.BytesIO(); img.save(bio,'PNG'); b=bytearray(bio.getvalue()); b[20:24]=struct.pack('>I',40)  # 高さを40に（CRCそのまま）
open('2_short.png','wb').write(b)
# 3 LSB
img=Image.new('RGB',(100,100),(90,140,200)); px=img.load()
bits=''.join(f'{c:08b}' for c in b'flag{lsb_steg_is_fun}'+b'\0')
i=0
for y in range(100):
  for x in range(100):
    r,g,bb=px[x,y]; ch=[r,g,bb]
    for k in range(3):
      if i<len(bits): ch[k]=(ch[k]&~1)|int(bits[i]); i+=1
    px[x,y]=tuple(ch)
img.save('3_lsb.png')
# 4 JPEG + EXIF
img=Image.new('RGB',(50,50),(10,200,10)); ex=Image.Exif(); ex[0x013b]=bytes.hex(b'flag{exif_artist_hex}'); ex[0x010e]='just a photo'
img.save('4_exif.jpg',exif=ex.tobytes(),comment=b'ZmxhZ3tqcGVnX2NvbW1lbnR9')
# 5 XOR全体
open('5_xor.bin','wb').write(bytes(c^0x37 for c in b'random header....the flag is flag{xor_whole_file} bye'))
# 6 gzip
open('6_text.gz','wb').write(gzip.compress(b'log line\n'*50+b'ctf4b{gzip_inside}\n'))
# 7 PDF
st=zlib.compress(b'BT /F1 12 Tf 72 712 Td (picoCTF{pdf_stream}) Tj ET')
open('7_doc.pdf','wb').write(b'%%PDF-1.4\n1 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n'%len(st)+st+b'\nendstream\nendobj\n%%EOF\n')
# 8 バイナリ（UTF-16と逆さま）
open('8_prog.exe','wb').write(b'MZ\x90\0'+os.urandom(200)+'flag{utf16_string}'.encode('utf-16le')+os.urandom(50)+b'}desrever_si_siht{galf'+os.urandom(30))
# 9 先頭が壊れたPNG＋拡張子ちがい
bio=io.BytesIO(); Image.new('RGB',(8,8)).save(bio,'PNG'); p=bytearray(bio.getvalue()); p[0:8]=b'\0'*8
open('9_broken.txt','wb').write(p)
# 10 暗号化ZIP
open('in.txt','w').write('flag{you_need_password}')
subprocess.run(['zip','-q','-P','secret','10_locked.zip','in.txt']); os.remove('in.txt')
print(os.listdir('.'))
