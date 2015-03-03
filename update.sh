#!/bin/bash

if [ ${PWD##*/} != "morgana-gh" ]; then
    echo "must run this in root of morgana-gh"
fi

script=`cat update.sh`

rm -rf *
cp -r ../morgana/dist/* .
cp -r assets static
echo "morgana.qax.io" > CNAME
echo "$script" > update.sh
chmod +x update.sh
