#!/bin/sh

cd /System/Library/Frameworks/ApplicationServices.framework/Frameworks/CoreGraphics.framework/Resources/

if [ ! -f WindowServer.sedarwin ]; then
    echo "SEDarwin is not installed on this system"
    exit
fi

if [ -f WindowServer.apple ]; then
    exit
fi

mv WindowServer WindowServer.apple
ln -s WindowServer.sedarwin WindowServer
