
MODULES = mod_socks4 mod_socks5 mod_authen mod_author mod_proxy mod_log mod_balance mod_filter mod_statistics mod_bandwidth mod_dump

.PHONY : all
all ::
	@for i in $(MODULES); do (cd $$i; $(MAKE) all); if test $$? -ne 0; then exit 1; fi; done

clean:
	for d in $(MODULES); do (cd $$d; $(MAKE) clean); done

distclean: clean
	for d in $(MODULES); do (cd $$d;  $(MAKE) distclean); done
	rm -f Makefile
