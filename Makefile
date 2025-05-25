
CFLAGS = -Wall -Wextra -Os -g -fno-strict-aliasing -ffunction-sections -fdata-sections -fvisibility=hidden -std=gnu99 -fno-stack-protector
LDFLAGS =
LIBS = -lpthread

all: gwhttpd2

gwhttpd2: gwhttpd2.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f gwhttpd2

.PHONY: all clean
