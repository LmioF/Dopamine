PYTHON ?= python3
PACKAGE = launchctl-roothide.deb
BOOTSTRAP = ../../Application/Dopamine/Resources/bootstrap_1900.tar.zst

package: $(PACKAGE)

$(PACKAGE): build.py compat.py $(BOOTSTRAP)
	$(PYTHON) build.py --bootstrap $(BOOTSTRAP) --output $@

clean:
	rm -f $(PACKAGE)

.PHONY: package clean
