#!/usr/bin/python

badchar1 = "\'"
badchar2 = "+"
string = input("Escribe la cadena ofuscada: ")
file = open('/app/converter/results/plaintext_payload.txt', 'a')

noquotes = string.replace(badchar1, "")
output = noquotes.replace(badchar2, "")

file.write(output)

print("done!")