CFLAGS = -Wall -Wextra -Os -g -fno-strict-aliasing -ffunction-sections \
	-fdata-sections -fvisibility=hidden -std=gnu99 -fno-stack-protector \
	-D_GNU_SOURCE
LDFLAGS =
DEPFLAGS = -MMD -MP -MF $@.d
LIBS = -lpthread

ifeq ($(SANITIZE),1)
	CFLAGS += -fsanitize=address -fsanitize=undefined
	LDFLAGS += -fsanitize=address -fsanitize=undefined
	LIBS += -static-libasan
endif

ifeq ($(LTO),1)
	CFLAGS += -flto
	LDFLAGS += -flto
endif

ifeq ($(STATIC),1)
	LDFLAGS += -static
endif

ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
else
	CFLAGS += -DNDEBUG
endif

GWHTTPD_CC_OBJ = \
	gwbuf.o \
	gwnet_http.o \
	gwnet_http1.o \
	gwnet_tcp.o \
	gwhttpd.o

all: gwhttpd

gwhttpd: $(GWHTTPD_CC_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS) $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) -c $< -o $@

-include $(GWHTTPD_CC_OBJ:.o=.o.d)

clean:
	rm -f *.o *.o.d gwhttpd

.PHONY: all clean
