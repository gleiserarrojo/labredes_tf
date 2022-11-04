all:
	gcc server.c checksum.c sniffer.c -o s

clean:
	rm -rf s