CFLAGS = -Wall -Wextra -Os -g -fno-strict-aliasing -ffunction-sections \
	-fdata-sections -fvisibility=hidden -std=gnu99 -fno-stack-protector \
	-Wno-unused-function -Wno-unused-variable -Wno-unused-parameter
LDFLAGS = -static-libasan
DEPFLAGS = -MMD -MP -MF $@.d
LIBS = -lpthread

ifeq ($(SANITIZE),1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
endif

GWHTTPD_CC_OBJ = \
	gwbuf.o \
	gwnet_http.o \
	gwnet_http1.o \
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
