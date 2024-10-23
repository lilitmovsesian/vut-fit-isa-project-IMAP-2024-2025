imapcl: imapcl.o
	gcc -Wall -Wextra -g imapcl.o -o imapcl -lssl -lcrypto

imapcl.o: imapcl.c
	gcc -Wall -Wextra -g -c imapcl.c -o imapcl.o

clean:
	rm -f imapcl.o imapcl

.PHONY: all clean
