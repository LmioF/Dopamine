all:
	@$(MAKE) -C libkrw-provider package
	@$(MAKE) -C libroot package
	@$(MAKE) -C basebin-link package
	@$(MAKE) -C launchctl package

clean:
	@$(MAKE) -C libkrw-provider clean
	@$(MAKE) -C libroot clean
	@$(MAKE) -C basebin-link clean
	@$(MAKE) -C launchctl clean

.PHONY: clean
