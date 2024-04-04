#!/usr/bin/python3

cadena = input("Escribe aquí tu cadena: ")
converter = cadena.replace("\\x00", "")

print(converter)

char = input("Quieres mirar otra cadena en texto plano? Si <s> No <n>: ")
while char == 's':
    cadena = input("Escribe otra cadena: ")
    converter = cadena.replace("\\x00", "")

    print(converter)

    char = input("Quieres mirar otra cadena en texto plano? Si <s> No <n>: ")
