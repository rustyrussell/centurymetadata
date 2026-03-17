#! /bin/sh
# Script to setup centurymetadata server directory skeleton

BASEDIR=/home/rusty/data/centurymetadata/v1

if [ ! -d "$BASEDIR" ]; then
    mkdir -p "$BASEDIR"
    chgrp www-data "$BASEDIR"
    chmod g+rwxs "$BASEDIR"
fi

# Create initial catch-all directory and bundle if not present
INITDIR="$BASEDIR/00-ff"
INITBUNDLE="$INITDIR/00-ff"

if [ ! -d "$INITDIR" ]; then
    mkdir "$INITDIR"
    chgrp www-data "$INITDIR"
    chmod g+rwxs "$INITDIR"
fi

if [ ! -d "$INITBUNDLE" ]; then
    mkdir "$INITBUNDLE"
    chgrp www-data "$INITBUNDLE"
    chmod g+rwxs "$INITBUNDLE"
fi

echo "Setup complete: $BASEDIR"
