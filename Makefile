CFLAGS=-Wall -Wshadow -Wno-int-to-void-pointer-cast -Wno-unused-parameter -g -fstack-protector-strong -fpie -I deps -std=c99
LDFLAGS=

.PHONY: cppcheck scan-build clean

vixfs: main.c deps/cmp/cmp.c
	$(CC) $(CFLAGS) -o $@ main.c deps/cmp/cmp.c $(LDFLAGS)

cppcheck:
	cppcheck --enable=all --inconclusive ./main.c

scan-build:
	scan-build -enable-checker security -enable-checker nullability -enable-checker alpha.security.ArrayBoundV2 -enable-checker alpha.valist -enable-checker alpha.core $(MAKE)

clean:
	rm -f vixfs
