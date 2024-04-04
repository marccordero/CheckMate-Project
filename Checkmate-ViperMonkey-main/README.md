# Que es ViperMonkey

ViperMonkey es una herramienta desarrollada en python y su función principal es analizar macros VBA.

## Como funciona ViperMonkey

ViperMonkey extrae la macro del documento y lo muestra por pantalla. 

![Macro](/Checkmate-ViperMonkey-main/images/macro_payload.png)

Después hay un apartado que muestra el payload encodeado en base64

![Base64](/Checkmate-ViperMonkey-main/images/base64_payload.png)

Otra cosa interesante que mostrará es una tabla con los IOC

![IOC1](/Checkmate-ViperMonkey-main/images/IOC_table.png)

![IOC2](/Checkmate-ViperMonkey-main/images/IOC_table2.png)

Y por último mostrará funciones que ejecuta que pueden ser también indicadores de compromiso

![PossibleIOC](/Checkmate-ViperMonkey-main/images/possible_IOC.png)

Sample utilizado: https://app.any.run/tasks/e472f974-4c58-428f-9159-016453f367d3/

https://www.virustotal.com/gui/file/e26b12859ce5d6654399ec144ba5196fa97bc04cf36d6ed3881501a9478b0338

## Setup

### Descargar repositorio

`git clone [Enlace del repositorio]`

### Construir la imagen

Dentro de la carpeta del repositorio poner:

`docker build -t vmonkey:latest .`

### Crear y ejecutar un contenedor

`docker run --name [nombre] -it [nombre de la imagen]`

### Entrar al contenedor

`docker exec -it [nombre del contenedor] /bin/bash`

### Apagar el contenedor 

`docker stop [nombre del contenedor]`

### Encender el contenedor

`docker start [nombre del contenedor]`

### Descomprimir samples

`unzip [archivo].zip`

### Ejecutar ViperMonkey

`vmonkey [archivo].doc`

#### Ejemplo 

`vmonkey 1word.doc`

### Ejecutar decoder

Este pequeño script en bash ubicado en converter/ pedirá el Payload en base64 y lo convertirá para que lo podamos leer.

`bash decoder.sh`

![Script](/Checkmate-ViperMonkey-main/images/decoder_script.png)

Una vez ejecutado el script en el directorio results/ habrá el archivo payload_decoded.txt

![DecodedScript](/Checkmate-ViperMonkey-main/images/decoder_result.png)

### Ejecutar deofuscador

Dentro del directorio converter/ hay otro script en python que lo que hace es limpiar los caracteres `'` y `+` para poder ver de mejor manera el payload. *IMPORTANTE PONER LA CADENA ENTRE COMILLAS DOBLES PARA QUE EL SCRIPT FUNCIONE. TAMBIÉN HAY QUE PASAR PREVIAMENTE EL CMDLET WRITE-HOST A LA CADENA. POWERSHELL VIENE INSTALADO DENTRO DEL CONTENEDOR*

`python cleaner.py`

![PythonDeobf](/Checkmate-ViperMonkey-main/images/python_script.png)

El script guarda el resultado en el directorio results/ como plaintext_payload.txt

![PlaintextResult](/Checkmate-ViperMonkey-main/images/plaintext.png)
