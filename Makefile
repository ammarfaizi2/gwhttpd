CFLAGS = -Wall -Wextra -O2 -g -fno-strict-aliasing -ffunction-sections \
	-fdata-sections -fvisibility=hidden -std=gnu99 -fno-stack-protector
LDFLAGS =
DEPFLAGS = -MMD -MP -MF $@.d
LIBS = -lpthread

ifeq ($(SANITIZE),1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
	LIBS += -static-libasan
endif

ifeq ($(LTO),1)
	CFLAGS += -flto=full
	LDFLAGS += -flto=full
endif

ifeq ($(STATIC),1)
	LDFLAGS += -static
endif

ifeq ($(RELEASE_MODE),1)
	CFLAGS += -DNDEBUG
else
	CFLAGS += -DDEBUG
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
