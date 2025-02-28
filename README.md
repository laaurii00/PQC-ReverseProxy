# PQC-ReverseProxy

Implementación Proxy inverso como Gateway de TLS para PQC.

## Contexto
La organización Open Quantum Safe (OQS) ha realizado un versiona del servidor web de código abierto, Nginx, el cual permite negociar claves y autenticación quantum-safe mediante TLS 1.3.
Esta imagen de nginx admite los algoritmos de intercambio de claves de seguridad cuántica, a día 28/02/2025:

    * BIKE: bikel1, bikel3, bikel5
    * CRYSTALS-Kyber: kyber512, kyber768, kyber1024
    * FrodoKEM: frodo640aes, frodo640shake, frodo976aes, frodo976shake, frodo1344aes, frodo1344shake
    * HQC: hqc128, hqc192, hqc256†programa cliente de cifrado seguro

Y, los algoritmos de firma digital de seguridad cuántica, a día 28/02/2025:

    * CRYSTALS-Dilithium:dilithium2*, dilithium3*, dilithium5*
    * Falcon:falcon512*, falcon1024*
    * SPHINCS-SHA2:sphincssha2128fsimple*, sphincssha2128ssimple*, sphincssha2192fsimple*, sphincssha2192ssimple, sphincssha2256fsimple, sphincssha2256ssimple
    * SPHINCS-SHAKE:sphincsshake128fsimple*, sphincsshake128ssimple, sphincsshake192fsimple, sphincsshake192ssimple, sphincsshake256fsimple, sphincsshake256ssimple

La implementación del lado cliente se ha realizado mediante la imagen Docker curl realizada por OQS, obteniendo un programa cliente quantum-safe. 

## Pasos
### 1.Instalación Docker Engine en Ubuntu
    apt  install docker.io
### 2.Instalación Nginx Server con PQC implementado con OQS
    docker pull openquantumsafe/nginx
### 3.Configuración del proxy inverso
Para la realización del servidor Nginx como proxy inverso, es necesario especificar la configuración mediante el fichero "nginx.conf", y a su vez especificar las claves PQC con las que se va a realizar la autenticación de la comunicación.
Estructura del fichero de configuración, "nginx.cnf":

        worker_processes auto;

        events {
            worker_connections 1024;
        }

        HTTPS server
        http {
            include       ../conf/mime.types;
            default_type  application/octet-stream;

            sendfile        on;
            keepalive_timeout  65;

            #Especificaciones del servidor
            server {
                listen        0.0.0.0:<Puerto de Escucha> ssl;

                access_log  /opt/nginx/logs/access.log;
                error_log   /opt/nginx/logs/error.log;

                ssl_certificate      /opt/nginx/pki/server.crt;
                ssl_certificate_key  /opt/nginx/pki/server.key;

                ssl_session_cache    shared:SSL:1m;
                ssl_session_timeout  5m;

                ssl_protocols TLSv1.3;
                ssl_ecdh_curve <KEM_METHOD>>;

                location /ENDPOINT {
                    proxy_pass https://IP_VM:PORT_VM/ENDPOINT;
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto $scheme;
                    proxy_ssl_certificate /opt/nginx/pki/proxy.crt;
                    proxy_ssl_certificate_key /opt/nginx/pki/proxy.key;
                }

                location /ENDPOINT-2 {
                    proxy_pass https://IP_VM:PORT_VM/ENDPOINT-2;
                    proxy_set_header Host $host;
                    proxy_set_header X-Real-IP $remote_addr;
                    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                    proxy_set_header X-Forwarded-Proto $scheme;
                    proxy_ssl_certificate /opt/nginx/pki/proxy.crt;
                    proxy_ssl_certificate_key /opt/nginx/pki/proxy.key;
                } 

                location / {
                    root   html;
                    index  index.html index.htm;
                }
            }
        }

Esta estructura permite establecer el proxy inverso recibiendo solicitudes HTTPS con certificados PQC y redireccionando estas al servicio que se desee mediante HTTPS tradicional.
Los parámetros clave a tener en cuenta en dicha implementación son:
* __Puerto de escucha del proxy:__ Se debe especificar el puerto en el que el servidor escuchará las solicitudes entrantes, al cual el cliente mediante el comando curl se debe comunicar. 
* __Rutas a los certificados PQC:__ En el apartado __ssl_certificate__ y __ssl_certificate_key__ se especifica la dirección exacta donde se encuentran almacenados las claves PQC. Si dichas claves se quieren generar fuera de la imagen docker, implementación recomendada, se debe generar un volumen que apunte los la carpeta de los certificados generados a la dirección de la imagen Docker "/opt/nginx/pki/".
* __Especificación del método KEM:__ En el apartado __ssl_ecdh_curve__ se debe especificar el método KEM mediante el cual se quiere establecer el handshake. Alguno de los métodos disponibles son: frodo976shake:frodo1344shake:p256_kyber512:kyber768:kyber1024:kyber512
* __Location:__ En el apartado location junto a / se especifica la directiva para que Nginx maneje las solicitudes, es decir, cualquier expresión regular que coincida con la expresión especificada será procesada por nginx. Dicha solicitud será reenviada a la dirección y puertos especificada en __proxy_pas__. Dicha redirección se realizará mediante el protocolo SSL/TLS tradicional, cuyas claves estan especificadas en los parámetros __proxy_ssl_certificate__ y __proxy_ssl_certificate_key__. 

### 4.Generación de claves PQC.
Como se ha mencionado en el paso anterior, se debe generar dos tipos de claves: las claves PQC para autentificar la comunicación HTTPS quantum-safe con el exterior, y claves tradicionales para autentificar la comunicación con el servidor final.
Se recomienda la generación de claves mediante linea de comandos "openssl", a modo de ejemplo:

    openssl req -x509 -new -newkey falcon1024 -keyout ca.key -out ca.crt -nodes  -subj "XXX" -days 3650 -config $openssl_conf

    openssl genpkey -algorithm falcon1024 -out nginx-server.key
    openssl req -new -key nginx-server.key -out nginx-server-csr.pem -nodes -config $openssl_conf
    openssl x509 -req -in nginx-server-csr.pem -CA ca.crt -CAkey ca.key -CAcreateserial -out nginx-server.crt -days 365

### 5.Instalación Curl con PQC implementado con OQS
    docker pull openquantumsafe/curl

### 6.Establecimiento de la comunicación
Se debe tener en cuenta que el certificado de autofirma implementado para la generación de claves PQC en el proxy inverso, debe estar disponible en la máquina virtual que vaya a trabajar como cliente.

A su vez, como se ha mencionado, para poder configurar y trabajar de forma persistente con las especificaciones definidas en el dichero "nginx.cnf" se deben establecer volúmenes. Al arrancar el contenedor openquantumsafe/nginx y openquantumsafe/curl con la directiva __-v__ /ruta/en/host:/ruta/en/contenedor, se consigue montar el directorio específico del host dentro del contenedor.

Comandos de arranque de los contenedores:

#### Proxy Inverso
    docker run -p <Puerto de Escucha>:<Puerto de Escucha> -v "/ruta/en/host/nginx-conf:/opt/nginx/nginx-conf" -v "/ruta/en/host/server-pki:/opt/nginx/pki" openquantumsafe/nginx

#### Cliente

    docker run -v "/ruta/en/host/ca.crt:/etc/ssl/certs/ca.crt" -it openquantumsafe/curl curl --cacert /etc/ssl/certs/ca.crt -X GET https://IP_VM:PORT_VM/ENDPOINT
