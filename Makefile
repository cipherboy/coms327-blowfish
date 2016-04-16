#Possible targets:
#
# all:				recompiles code, runs tests
# format: 			formats source files
# build:			builds and compiles code
# clean: 			removes old object files
# changelog: 		updates changelog
# run:				makes all, executes code
# execute:			runs all test vectors

VERSION = Scheel_Alexander.assignment-2
NAME = blowfish
CXX ?= g++
CXXFLAGS = -O0 -mtune=native -Wall -std=c++11 -ggdb -fdiagnostics-color=always
LFLAGS = -lm -lncurses

CXXSOURCES = $(wildcard src/*.cc)
CXXOBJECTS = $(CXXSOURCES:.cc=.o)
CXXMAINSOURCES = $(wildcard main/*.cc)
CXXMAINOBJECTS = $(CXXMAINSOURCES:.cc=.o)
CXXTESTSOURCES = $(wildcard tests/*.cc)
CXXTESTOBJECTS = $(CXXTESTSOURCES:.cc=.o)

# Default target
run: all execute

all: format changelog build

clean:
	rm -rf ./*/*.o ./bin/*.dSYM ./autom4te.cache ./configure ./bin/tests ./bin/$(NAME)

format:
	astyle --style=linux --lineend=linux --max-code-length=78 ./*/*.cc || true
	astyle --style=linux --lineend=linux --max-code-length=78 ./*/*.hh || true

	rm -f ./*/*.orig

changelog: .git
	git log --source --log-size --all --cherry --decorate=full --full-history \
		--date-order --show-notes --relative-date  --abbrev-commit --children \
		--stat --no-color > CHANGELOG

build: main

main: $(CXXOBJECTS) $(CXXMAINOBJECTS) $(CXXTESTOBJECTS)
	$(CXX) $(LFLAGS) $(CXXOBJECTS) $(CXXMAINOBJECTS) -o bin/$(NAME)
	$(CXX) $(LFLAGS) $(CXXOBJECTS) $(CXXTESTOBJECTS) -o bin/tests

%.o: %.cc
	$(CXX) -c $(CXXFLAGS) $< -o $@

gzip:
	rm -rf ../$(VERSION).tar ../$(VERSION).tar.gz
	tar -cf ../$(VERSION).tar ../$(VERSION)
	gzip ../$(VERSION).tar

execute:
	./bin/tests || true
