#!/bin/sh

if [ -f /.attribute/system/sebsd ]; then
    echo "Warning, attribute backing file already exists, leaving it alone."
    echo "If you want to re-initialize it, remove /.attribute/system/sebsd"
    echo "and re-run this script."
    exit;
fi

if [ ! -x /usr/bin/extattrctl ]; then
    echo "Error, no /usr/bin/extattrctl, this script only creates"
    echo "a backing file on SEDarwin systems"
    exit;
fi

mkdir -p /.attribute/system

/usr/bin/extattrctl initattr -p / -i "system_u:object_r:file_t" \
    256 /.attribute/system/sebsd
