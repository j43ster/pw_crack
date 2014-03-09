#!/bin/bash

for i in "$@"
do
  for j in $(seq -f "%02g" 1 37)
  do
     host=${i}x${j}
     #echo trying $host
     if `ssh -q -o ConnectTimeout=2 $host exit` > /dev/null
     then
        echo $host
     fi
  done
done
