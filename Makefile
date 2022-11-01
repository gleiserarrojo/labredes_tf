all:
	gcc server.c checksum.c -o s

clean:
	rm -rf s