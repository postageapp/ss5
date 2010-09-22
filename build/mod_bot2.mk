
all:	$(MODULE) $(MGR)

$(MODULE) : $(MODULEOBJ)
	$(CC) $(CFLAGS) -o $(MODULE) $(MODULEOBJ) $(LIBS)

$(MGR) : $(MGROBJ)
	$(CC) $(MGECFLAGS) -o $(MGR) $(MGROBJ) $(LIBS2)

clean:
	rm -f $(MODULEOBJ)
	rm -f $(MODULE)
	rm -f $(MGROBJ)
	rm -f $(MGR)

distclean: clean
	rm -f Makefile
