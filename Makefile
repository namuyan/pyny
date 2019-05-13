#
# Makefile
# Copyright (C) 2006 Pyny Project.
#
# $Id: Makefile 3 2006-03-06 01:03:41Z fuktommy $
#

all:
#	python setup.py build
	@echo do nothing

clean:
	rm -Rf build dist root
	rm -Rf cache log run
	find . -name "*.py[co]" | xargs rm -f

distclean: clean
	find . -name "*~" -o -name "#*" -o -name ".#*" | xargs rm -f
