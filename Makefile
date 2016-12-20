env: setup.py
	virtualenv env
	env/bin/pip install .
	env/bin/pip list --outdated

lint:
	./setup.py flake8

test: env lint
	env/bin/python test/test.py -v

test3: env
	python3 ./test/test.py -v

init_docs:
	cd docs; sphinx-quickstart

docs:
	$(MAKE) -C docs html

install:
	-rm -rf dist
	python setup.py bdist_wheel
	pip install --upgrade dist/*.whl

.PHONY: test release docs lint

include common.mk
