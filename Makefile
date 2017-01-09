SRC = *.c
CFLAGS = -Wall

all: wimon

wimon:
	gcc $(CFLAGS) -o wimon $(SRC) -lpcap

debug:
	gcc  $(CFLAGS) -g -o wimon $(SRC) -lpcap
	valgrind --tool=memcheck --leak-check=yes wimon
	
.PHONY: clean
clean:
	rm -f wimon *.o

