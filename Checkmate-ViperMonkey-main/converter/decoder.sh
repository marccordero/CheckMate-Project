#!/bin/bash

echo Escribe la cadena en base64:

read encoded

echo $encoded | base64 -d > /app/converter/results/payload_Encoded.txt

echo "done!"
