#! /bin/sh
# Script to setup / update centurymetadata dir min/maxdepth

BASEDIR=$(dirname "$(realpath "$0")")
BASEDIR=$(realpath "$BASEDIR/../../..")

if [ ! -d "$BASEDIR" ]; then
    mkdir "$BASEDIR"
    chgrp www-data "$BASEDIR"
    chmod g+rwxs www-data "$BASEDIR"
fi

# This is actually num + 1
NUM=$(find "$BASEDIR" -type d | wc -l)

# Make < 1000 per bucket
DEPTH=1
N="$NUM"
while [ "$N" -gt 1000 ]; do
    DEPTH=$((DEPTH + 1))
    N=$((N / 16))
done

if ! mv "$BASEDIR"/maxdepth "$BASEDIR"/mindepth; then
    echo "$DEPTH" > "$BASEDIR"/mindepth
fi

echo "$DEPTH" > "$BASEDIR"/maxdepth
echo "Depth=$DEPTH for $NUM"
