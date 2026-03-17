#! /usr/bin/make

default: README.md python/README.md web/index.html python/centurymetadata/constants.py

check:
	cd python && uv run pytest $(PYTEST_ARGS)

check-source: check-flake8 check-mypy

check-flake8:
	cd python && uv run flake8 --ignore=E501,E731,W503 centurymetadata tests

check-mypy:
	cd python && uv run mypy --ignore-missing-imports --disallow-untyped-defs --disallow-incomplete-defs centurymetadata tests

TAGS:
	etags `find . -name '*.py'`

web/index.html: templates/index.html.src templates/convert-src vars Makefile
	templates/convert-src web vars $< > $@

README.md: templates/README.md.src templates/convert-src vars Makefile
	templates/convert-src markdown vars $< > $@

python/README.md: README.md
	cp $< $@

python/centurymetadata/constants.py: templates/constants.py.src vars Makefile
	templates/convert-src raw vars $< > $@

upload: web/index.html
	rsync -av web/ ozlabs.org:/home/rusty/www/centurymetadata.org/htdocs/
	git push -f ssh://ozlabs.org/home/rusty/centurymetadata/ master:incoming
	ssh ozlabs.org 'cd ~/centurymetadata && git checkout master && git merge --ff-only incoming && cd python && uv sync && sed "1s|.*|#! /home/rusty/centurymetadata/python/.venv/bin/python3|" centurymetadata/server/server.py > ~/www/centurymetadata.org/cgi/server.py && chmod +x ~/www/centurymetadata.org/cgi/server.py'

