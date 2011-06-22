version		= 0.1
dirname		= cmd5-$(version)
tarname		= $(dirname).tar.gz

all:		cmd5

cmd5:		cmd5.o hmac_md5.o md5c.o base64.o
		gcc -o cmd5 cmd5.o hmac_md5.o md5c.o base64.o

cmd5.o:		cmd5.c

hmac_md5.o:	hmac_md5.c

md5c.o:		md5c.c

base64.o:	base64.c

clean:
		-rm cmd5 cmd5.o hmac_md5.o md5c.o base64.o

distclean:	clean

dist:		distclean
		lynx --dump README.html > README
		(cd ..; ln -s cmd5 $(dirname))
		(cd ..; tar zhcvf $(tarname) $(dirname))
		(rm ../$(dirname))

