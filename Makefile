PACKAGE := vpn_kill_users
.DEFAULT: test
.PHONY: all test coverage pep8 pylint rpm clean
TEST_FLAGS_FOR_SUITE := -m unittest discover -f -s test

all: test

test:
	python -B $(TEST_FLAGS_FOR_SUITE)

coverage:
	coverage run $(TEST_FLAGS_FOR_SUITE)

pep8:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pep8 {} \;

pylint:
	@find ./* `git submodule --quiet foreach 'echo -n "-path ./$$path -prune -o "'` -type f -name '*.py' -exec pylint -r no --disable=locally-disabled {} \;

rpm:
	fpm -s python -t rpm --no-python-fix-name --rpm-dist "$$(rpmbuild -E '%{?dist}' | sed -e 's#^\.##')" --iteration 1 setup.py
	@rm -rf build $(PACKAGE).egg-info

clean:
	rm -f *.pyc test/*.pyc
	rm -rf build $(PACKAGE).egg-info
