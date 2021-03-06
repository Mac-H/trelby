.PHONY = dist

BINDIR = $(DESTDIR)/opt/trelby
DESKTOPDIR = $(DESTDIR)/usr/share/applications

dist: names.txt.gz dict_en.dat.gz manual.html
	./gen_linux_dist.sh
	debuild -us -uc -b

names.txt.gz: names.txt
	gzip -c names.txt > names.txt.gz

dict_en.dat.gz: dict_en.dat
	gzip -c dict_en.dat > dict_en.dat.gz

manual.html: doc/*
	make -C doc && mv doc/book.html manual.html

clean:
	rm -f src/*.pyc names.txt.gz dict_en.dat.gz manual.html
	dh_clean

install:
	mkdir -p $(BINDIR)
	rm -f src/*.pyc
	cp -r src/ trelby.desktop names.txt.gz dict_en.dat.gz sample.trelby manual.html fileformat.txt LICENSE INSTALL README resources $(BINDIR)
	cp trelby.desktop $(DESKTOPDIR)

uninstall:
	rm -f $(BINDIR)
