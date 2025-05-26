CFLAGS = -Wall -Wextra -Os -g -fno-strict-aliasing -ffunction-sections -fdata-sections -fvisibility=hidden -std=gnu99 -fno-stack-protector -flto
LDFLAGS = -flto
DEPFLAGS = -MMD -MP -MF $@.d
LIBS = -lpthread

GWHTTPD_CC_OBJ = \
	gwbuf.o \
	gwnet_http.o \
	gwnet_tcp.o \
	gwhttpd2.o

all: gwhttpd2

gwhttpd2: $(GWHTTPD_CC_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

-include $(GWHTTPD_CC_OBJ:.o=.o.d)

clean:
	rm -f *.o *.o.d gwhttpd2

.PHONY: all clean
