def part(f,a,b):
    s=open(f).read(); return s[s.index(a):s.index(b)]
t=open('template.html').read().replace('/*CORE*/',part('core.js','/*CORE_START*/','/*CORE_END*/')).replace('/*FCORE*/',part('fcore.js','/*FCORE_START*/','/*FCORE_END*/'))
open('index.html','w').write(t)
