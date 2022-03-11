#!/usr/bin/env bash

[ -r .env ] && source .env
exec_name=`basename "$(pwd)"`
rm -f "$exec_name"
flags='-s -w'
[ -d ".git" ] && {
    govvv build -ldflags "${flags}"
} || {
    go build -ldflags "${flags}"
}
