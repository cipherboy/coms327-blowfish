#Possible targets:
#
# all:				recompiles code, runs tests
# format: 			formats source files
# build:			builds and compiles code
# clean: 			removes old object files
# changelog: 		updates changelog
# run:				makes all, executes code
# execute:			runs current executable

VERSION = Scheel_Alexander.assignment-2
NAME = blowfish
CXX ?= g++
CXXFLAGS = -O0 -mtune=native -Wall -std=gnu++98 -ggdb -fdiagnostics-color=always
LFLAGS = -lm -lncurses

CXXSOURCES = $(wildcard src/*.cc)
CXXOBJECTS = $(CXXSOURCES:.cc=.o)

# Default target
run: all execute

all: format changelog build

clean:
	rm -rf ./*/*.o ./bin/*.dSYM ./autom4te.cache ./configure ./bin/tests-$(NAME) ./bin/$(NAME)

format:
	astyle --style=linux ./src/*.c || true
	astyle --style=linux ./src/*.cc || true
	astyle --style=linux ./src/*.h || true
	rm -f ./src/*.orig

changelog: .git
	git log --source --log-size --all --cherry --decorate=full --full-history \
		--date-order --show-notes --relative-date  --abbrev-commit --children \
		--stat --no-color > CHANGELOG

build: main

main: $(CXXOBJECTS)
	$(CXX) $(LFLAGS) $(CXXOBJECTS) -o bin/$(NAME)

%.o: %.cc
	$(CXX) -c $(CXXFLAGS) $< -o $@

gzip:
	rm -rf ../$(VERSION).tar ../$(VERSION).tar.gz
	tar -cf ../$(VERSION).tar ../$(VERSION)
	gzip ../$(VERSION).tar

execute:
	./bin/$(NAME) || true
