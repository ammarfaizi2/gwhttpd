
CXXFLAGS = -ggdb3 -Wall -Wextra -O2 -fno-exceptions

ifeq ($(SANITIZE_BUILD),1)
	CXXFLAGS += "-fsanitize=address -DUSE_ASAN=1"
endif

gwhttpd: gwhttpd.cpp
	$(CXX) $(CXXFLAGS) -o $(@) $(^)

clean:
	rm -vf gwhttpd
