# Que es Oletools

Oletools es es un conjunto de herramientas programadas en python que sirven para analizar documentos de tipo OLE. Es una herramienta bastante similar a la ViperMonkey solo que esta es mas sencilla ya que hay funciones que no tiene como la de coger todo el payload en base64 y mostrarlo. La información que muestra es el código visual basic de la macro sin necesidad de ejecutarla.

Oletools esta compuesto por las herramientas: Oleid, olevba, MacroRaptor, msodde, pyxswf, oleobj, rtfobj, olebrowse, olemeta, oletimes, oledir y olemap.

## Como funciona olevba

Olevba es la herramienta principal de Oletools. Una vez ejecutado Olevba, esta te extrae el código fuente de la macro escrito en visual basic.

![Macro](/Checkmte-Oletools-main/images/macro_payload.png)

Este ejemplo indica que al abrir el documento con Document_Open() se ejecutaría toda la cadena en base64

Lo siguiente que muestra es una tabla de indicadores de compromiso de lo que ejecuta la macro

![IOC1](/Checkmte-Oletools-main/images/IOC_table.png)

En este ejemplo se puede ver que que hay funciones en base64, que es cierto ya que toda la macro está con el encoding base64. También hay una función Call al principio de la macro que parece que está llamando a la siguiente función. Luego hay otra función que se llama showwindow que puede esconder o mostrar ventanas.

## Setup

### Descagar repositorio

`git clone [enlace]`

### Construir la imagen

`docker build -t ole .`

### Crear y ejecutar el contenedor

`docker run --name [nombre del contenedor] -it [nombre de la imagen]`

### Iniciar el contenedor en caso de tenerlo montado

`docker start [nombre del contenedor]`

### Entrar al contenedor una vez iniciado

`docker exec -it [nombre del contenedor] bash`

### Apagar el contenedor

`docker stop [nombre del contenedor]`

### Descomprimir samples

`unzip [archivo.zip]`

### Ejecutar Olevba

`olevba [archivo].docx`

### Ejemplo

`olevba 1word.doc`

### Ejecutar decoder

Este pequeño script en bash ubicado en converter/ pedirá el Payload en base64 y lo convertirá para que lo podamos leer.

`bash decoder.sh`

![Script](/Checkmte-Oletools-main/images/decoder_script.png)

Una vez ejecutado el script en el directorio results/ habrá el archivo payload_decoded.txt

![DecodedScript](/Checkmte-Oletools-main/images/decoder_result.png)

### Ejecutar deofuscador

Dentro del directorio converter/ hay otro script en python que lo que hace es limpiar los caracteres `'` y `+` para poder ver de mejor manera el payload. *IMPORTANTE PONER LA CADENA ENTRE COMILLAS DOBLES PARA QUE EL SCRIPT FUNCIONE. TAMBIÉN HAY QUE PASAR PREVIAMENTE EL CMDLET WRITE-HOST A LA CADENA. POWERSHELL VIENE INSTALADO DENTRO DEL CONTENEDOR*

`python cleaner.py`

![PythonDeobf](/Checkmte-Oletools-main/images/python_script.png)

El script guarda el resultado en el directorio results/ como plaintext_payload.txt

![PlaintextResult](/Checkmte-Oletools-main/images/plaintext.png)