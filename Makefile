test_deps:
	pip install coverage flake8 wheel

lint: test_deps
	flake8 $$(python setup.py --name) test
	mypy --install-types
	mypy $$(python setup.py --name)

test: test_deps lint
	coverage run --source=$$(python setup.py --name) ./test/test.py

init_docs:
	cd docs; sphinx-quickstart

docs:
	sphinx-build docs docs/html

install: clean
	pip install wheel
	python setup.py bdist_wheel
	pip install --upgrade dist/*.whl

clean:
	-rm -rf build dist
	-rm -rf *.egg-info

.PHONY: lint test test_deps docs install clean

include common.mk
