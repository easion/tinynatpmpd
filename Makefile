
all: natpmpd

CC=$(COMPILE_PREFIX)gcc
AR=$(COMPILE_PREFIX)ar rcs

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o : %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

OBJS = natpmp.o main.o firewall.o iface.o

# 
natpmpd:  $(OBJS)
	$(CC) -o natpmpd $(LDFLAGS) $(OBJS) -levent # -levent_core


clean: 
	rm *.o natpmpd
