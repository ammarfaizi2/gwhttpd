
CFLAGS = -Wall -Wextra -Os -g -fsanitize=address
LDFLAGS =
LIBS = -lpthread

all: gwhttpd2

gwhttpd2: gwhttpd2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f gwhttpd2

.PHONY: all clean
