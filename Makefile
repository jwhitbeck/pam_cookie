CFLAGS:=-Wall -fPIC
CACHE_DIR:=/var/cache/pam_cookies

all: pam_cookie.so

pam_cookie.so: pam_cookie.o
	ld -x --shared -o $@ $^ -lpam -lssl

install: pam_cookie.so
	install --mode 644 --owner root --group root -D $< /lib/security/$<
	install --mode 2770 --owner root --group root -d $(CACHE_DIR)

clean:
	rm *.o *.so