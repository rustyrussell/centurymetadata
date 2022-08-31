#! /usr/bin/make

PYTHONFILES := $(shell find python -path python/centurymetadata/key.py -o \( -name '*.py' -print \) )
POSSIBLE_PYTEST_NAMES=pytest-3 pytest3 pytest
PYTEST := $(shell for p in $(POSSIBLE_PYTEST_NAMES); do if type $$p > /dev/null; then echo $$p; break; fi done)

default: README.md web/index.html python/centurymetadata/constants.py

check-pytest-found:
	@if [ -z "$(PYTEST)" ]; then echo "Cannot find any pytest: $(POSSIBLE_PYTEST_NAMES)" >&2; exit 1; fi

check: check-pytest-found
	cd python && $(PYTEST) $(PYTEST_ARGS)

check-source: check-flake8 check-mypy

check-flake8:
	flake8 --ignore=E501,E731,W503 $(PYTHONFILES)

check-mypy:
	mypy --ignore-missing-imports --disallow-untyped-defs --disallow-incomplete-defs $(PYTHONFILES)

TAGS:
	etags `find . -name '*.py'`

web/index.html: templates/index.html.src templates/convert-src vars Makefile
	templates/convert-src web vars $< > $@

README.md: templates/README.md.src templates/convert-src vars Makefile
	templates/convert-src markdown vars $< > $@

python/centurymetadata/constants.py: templates/constants.py.src vars Makefile
	templates/convert-src raw vars $< > $@

upload: web/index.html python/centurymetadata/server/server.py
	rsync -av web/ ozlabs.org:/home/rusty/www/centurymetadata.org/htdocs/
	rsync python/centurymetadata/server/server.py ozlabs.org:www/centurymetadata.org/cgi/
