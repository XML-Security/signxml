SHELL=/bin/bash

env: setup.py
	virtualenv env
	env/bin/pip install .
	env/bin/pip list --outdated

test: env
	-pylint -E signxml
	env/bin/python test/test.py -v

test3: env
	python3 ./test/test.py -v

release: docs
	python setup.py sdist bdist_wheel upload -s -i D2069255

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install:
	./setup.py install

.PHONY: test release docs
