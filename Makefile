SRC = *.c
CFLAGS = -Wall

all: wimon

wimon:
	gcc $(CFLAGS) -o wimon $(SRC) -lpcap

.PHONY: clean
clean:
	rm -f wimon *.o

