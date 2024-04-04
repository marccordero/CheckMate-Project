# Que es YARA

YARA es una herramienta creada por VirusTotal que sirve para la detección de malware a través de las strings del programa.

## Como funciona YARA

YARA funciona a través de reglas, las reglas buscan strings dentro de los programas. Una vez las encuentran ejecutan condiciones.

La sintaxis de las reglas es la siguiente:

```
rule nombre de la regla {
    meta:
        Author = "Creador de la regla"
        Description = "Descripción sobre la regla" 

    strings:
        $cadena1 = "DoYouWantToHaveSexWithCuongDong" 
        $cadena2 = ".babyk" 
        $cadena3 = "ADMIN$" 
        $cadena4 = "/c vssadmin.exe delete shadows /all /quiet"

    condition:
        $cadena1 or $cadena2 or $cadena3 or $cadena4
}
```

Las reglas de YARA pueden tener tanto cadenas de texto como hexadecimales.

## Creación de reglas

Las reglas de YARA son bastante sencillas de crear, solo hay que seguir la siguiente sintaxis:

```
rule nombre de la regla {
    meta:
        Author = "Creador de la regla"
        Description = "Descripción sobre la regla" 

    strings:
        $cadena1 = "DoYouWantToHaveSexWithCuongDong" 
        $cadena2 = ".babyk" 
        $cadena3 = "ADMIN$" 
        $cadena4 = "/c vssadmin.exe delete shadows /all /quiet" 

    condition:
        $cadena1 or $cadena2 or $cadena3 or $cadena4
}
```

Una cosa que hay que tener en cuenta a la hora de crear las cadenas es el tipo de cadena que es (Unicode o ASCII). En el caso de ser una cadena unicode hay que añadir **fullword wide** o **wide**.

```
rule syntaxTest {
    meta:
        Author = "Creador de la regla"
        Description = "Descripción sobre la regla" 

    strings: 
        $cadena = ".babyk" fullword wide

    condition:
        $cadena
}
```

Lo que hará YARA será encodear la cadena con 2 bytes \x00. Así lo mostrará:

`0x2e74:$ext: .\x00b\x00a\x00b\x00y\x00k\x00`

Si es una cadena ASCII no hace falta poner nada:

```
rule syntaxTest {
    meta:
        Author = "Creador de la regla"
        Description = "Descripción sobre la regla" 

    strings: 
        $cadena = "DoYouWantToHaveSexWithCuongDong"

    condition:
        $cadena
}
```

`0x3040:$mutex: DoYouWantToHaveSexWithCuongDong`

## Setup

### Descargar repositorio

`git clone [enlace]`

### Construir la imagen

`docker build -t yara:latest .`

### Crear y ejecutar el contenedor

`docker run --name [nombre del contenedor] -it [nombre de la imagen]`

### Iniciar el contenedor en caso de tenerlo montado

`docker start [nombre del contenedor]`

### Entrar al contenedor una vez iniciado

`docker exec -it [nombre del contenedor] sh`

### Apagar el contenedor

`docker stop [nombre del contenedor]`

### Descomprimir samples

`7z x -p[contraseña] archivo.zip`

### Ejecutar YARA

`yara -s [/rules/regla.yar] [/samples/malware.exe]`

#### Ejemplo

`yara -s /rules/babuk.yar /malware/e_win.exe`

### Eliminar el double byte encoding

El double byte encoding aparece en las cadenas de texto unicode. Para eliminar ese encoding hemos creado un pequeño script en python que lo elimina de la cadena

`python3 Converter/convertidor.py`

Aparecerá un mensaje de texto diciendo que peguemos la cadena, la pegamos y el script elimina el encoding

`Escribe aquí tu cadena: .\x00b\x00a\x00b\x00y\x00k\x00`

`.babyk`
