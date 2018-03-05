all: rpmfile2
clean:
	rm -f rpmfile2

SRC = rpmfile2.c cpioproc.c
HDR = errexit.h cpioproc.h

RPM_OPT_FLAGS ?= -O2 -g -Wall
LTO = -fwhole-program -flto
LIBS = -lrpmcpio -lmagic -lpthread
DEFS = -D_GNU_SOURCE

rpmfile2: $(SRC) $(HDR)
	$(CC) $(RPM_OPT_FLAGS) $(LTO) $(DEFS) -o $@ $(SRC) $(LIBS)
