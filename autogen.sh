#!/bin/sh
mkdir -p m4
touch NEWS README AUTHORS ChangeLog
intltoolize --automake --force --copy
autoreconf --force --install -I config -I m4
