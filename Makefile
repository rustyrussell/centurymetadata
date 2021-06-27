#! /usr/bin/make

PYTHONFILES := $(shell find python -path python/centurymetadata/key.py -o \( -name '*.py' -print \) )
POSSIBLE_PYTEST_NAMES=pytest-3 pytest3 pytest
PYTEST := $(shell for p in $(POSSIBLE_PYTEST_NAMES); do if type $$p > /dev/null; then echo $$p; break; fi done)

default: check-source check

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

web/index.html: README.md Makefile
	echo '<html><head><title>centurymetadata.org: Long-term Bitcoin Metadata Storage</title></head><body>' > $@
	python3 -m markdown README.md >> $@ || $(RM) $@
	echo '</body></html>' >> $@


upload: web/index.html
	rsync -av web/ ozlabs.org:/home/rusty/www/centurymetadata.org/htdocs/
