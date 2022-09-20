CC=gcc
EDCFLAGS= -O2 -I ./ -I ./include `pkg-config libzyre --cflags` `pkg-config libczmq --cflags` `pkg-config libzmq --cflags` $(CFLAGS)
EDLDFLAGS= `pkg-config libzyre --libs` `pkg-config libczmq --libs` `pkg-config libzmq --libs` $(LDFLAGS)

objs = src/peernet.o utilities/md5sum.o test.o

all: $(objs)
	$(CC) -o test.out $(objs) $(EDLDFLAGS)

%.o: %.c
	$(CC) -o $@ -c $< $(EDCFLAGS)

clean:
	rm -vf $(objs)
	rm *.out