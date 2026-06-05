#!/bin/sh
echo "Waiting for SSH on port 2222..."
i=0
while [ $i -lt 120 ]; do
  docker exec thesis-workspace nc -z localhost 2222 2>/dev/null
  if [ $? -eq 0 ]; then
    echo "SSH ready after ${i}s"
    exit 0
  fi
  i=$((i + 5))
  sleep 5
  echo -n "."
done
echo " TIMEOUT"
exit 1
