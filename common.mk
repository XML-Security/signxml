SHELL=/bin/bash -c 'set -eo pipefail; [[ -f environment ]] && source environment; shift; eval $$@' $@

release_major:
	$(eval export TAG=$(shell git describe --tags --match 'v*.*.*' | perl -ne '/^v(\d)+\.(\d)+\.(\d+)+/; print "v@{[$$1+1]}.0.0"'))
	$(MAKE) release

release_minor:
	$(eval export TAG=$(shell git describe --tags --match 'v*.*.*' | perl -ne '/^v(\d)+\.(\d)+\.(\d+)+/; print "v$$1.@{[$$2+1]}.0"'))
	$(MAKE) release

release_patch:
	$(eval export TAG=$(shell git describe --tags --match 'v*.*.*' | perl -ne '/^v(\d)+\.(\d)+\.(\d+)+/; print "v$$1.$$2.@{[$$3+1]}"'))
	$(MAKE) release

release: docs
	@if [[ -z $$TAG ]]; then echo "Use release_{major,minor,patch}"; exit 1; fi
	$(eval REMOTE=$(shell git remote get-url origin | perl -ne '/(\w+\/\w+)[^\/]+$$/; print $$1'))
	$(eval GIT_USER=$(shell git config --get user.email))
	$(eval RELEASES_API=https://api.github.com/repos/${REMOTE}/releases)
	$(eval UPLOADS_API=https://uploads.github.com/repos/${REMOTE}/releases)
	echo git clean -x --force $$(basename ${REMOTE})
	git tag --sign --annotate ${TAG}
	git push --follow-tags
	http --auth ${GIT_USER} ${RELEASES_API} tag_name=${TAG} name=${TAG} body="$$(git tag --list ${TAG} -n99 | perl -pe 's/^\S+\s*// if $$. == 1' | sed 's/^\s\s\s\s//')"
	$(MAKE) install
	http --auth ${GIT_USER} POST ${UPLOADS_API}/$$(http --auth ${GIT_USER} ${RELEASES_API}/latest | jq .id)/assets name==$$(basename dist/*.whl) label=="Python Wheel" < dist/*.whl
	$(MAKE) pypi_release

pypi_release:
	python setup.py sdist bdist_wheel upload --sign

.PHONY: release
