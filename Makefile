APP=SA-ctf_registration
VERSION=1.3.2
DIST=dist

.PHONY: test validate package clean

test:
	python3 -m unittest discover -s tests -v

validate:
	python3 -m py_compile bin/registration_core.py bin/registration_content.py bin/registration_rest.py
	python3 -m unittest discover -s tests -v

package: validate
	rm -rf $(DIST)
	mkdir -p $(DIST)
	tar --exclude='$(APP)/dist' --exclude='$(APP)/.git' --exclude='$(APP)/local' --exclude='$(APP)/tests' --exclude='*/__pycache__' --exclude='*.pyc' -C .. -czf $(DIST)/$(APP)-$(VERSION).spl $(APP)

clean:
	rm -rf $(DIST) __pycache__ bin/__pycache__ tests/__pycache__
