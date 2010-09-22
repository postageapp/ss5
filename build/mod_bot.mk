
all:	$(MODULE)

$(MODULE) : $(MODULEOBJ)
	$(CC) $(CFLAGS) -o $(MODULE) $(MODULEOBJ) $(LIBS)

clean:
	rm -f $(MODULEOBJ)
	rm -f $(MODULE)

distclean: clean
	rm -f Makefile
