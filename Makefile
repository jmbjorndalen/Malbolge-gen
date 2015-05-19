CFLAGS = -Wall -O2 -g # -pg
LDFLAGS = -static
TARGS = mbolge-gen interp-orig

all: $(TARGS)

clean:
	rm -f $(TARGS)

.c.o: %.c *.h
	$(CC) $(CFLAGS) -c $<

.cpp.o: %.cpp *.h
	c++ $(CFLAGS) -c $< 

mbolge-gen: mbolge-gen.cpp
	c++ $(CFLAGS) -o $@ $^  $(LDFLAGS)

interp-orig: interp-orig.c
	cc $(CFLAGS) -o $@ $^ $(LDFLAGS)