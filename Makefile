SRC = wimon.c radiotap.c
CFLAGS = -Wall

all: wimon gip

wimon:
	gcc $(CFLAGS) -o wimon $(SRC) -lpcap

debug:
	gcc  $(CFLAGS) -g -o wimon $(SRC) -lpcap
	valgrind --tool=memcheck --leak-check=yes wimon

gip:
	gcc -Wall -o gip gip.c radiotap.c -lpcap
	
.PHONY: clean
clean:
	rm -f wimon gip *.o
	

