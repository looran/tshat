#!/bin/bash

trace() { echo "# $*"; "$@"; }

dump=$(gcore $(pgrep tshat) | grep "Saved core" | cut -d' ' -f 3-)
trace ls -lh $dump
trace rg -a -c aaaaaaaaaaaa $dump
trace rg -a -c eeeeeeeeeeee $dump
trace wxHexEditor $dump &
