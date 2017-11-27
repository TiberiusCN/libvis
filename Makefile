CC=
CFLAGS=-c

libvis:
	$(CC)gcc $(CFLAGS) libvis.c -o out/libvis.o
	$(CC)ar rc out/libvis.a out/libvis.o
	$(CC)ranlib out/libvis.a
