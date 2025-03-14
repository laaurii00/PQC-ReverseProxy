Copyright 2025 Telefónica Innovación Digital (laura.dominguez.cespedes@telefonica.com)
 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied. See the License for the specific language governing
permissions and limitations under the License.

# PQC-Reverse Proxy

Reverse Proxy implementation with Quamtum-Safe TLS gateway. This repository describe the implementation to perform the configuration of a reverse proxy, allows nginx to negotiate quantum-safe keys and use quantum-safe authentication using TLS 1.3.

## Context
The Open Quantum Safe (OQS) organization has made a version of the open source web server, Nginx, which allows key negotiation and quantum-safe authentication through TLS 1.3.
This nginx image supports the quantum security key exchange algorithms, with date 28/02/2025:

    * BIKE: bikel1, bikel3, bikel5
    * CRYSTALS-Kyber: kyber512, kyber768, kyber1024
    * FrodoKEM: frodo640aes, frodo640shake, frodo976aes, frodo976shake, frodo1344aes, frodo1344shake
    * HQC: hqc128, hqc192, hqc256†programa cliente de cifrado seguro

And, qunatum-safe digital signature algorithms, with date 28/02/2025:

    * CRYSTALS-Dilithium:dilithium2*, dilithium3*, dilithium5*
    * Falcon:falcon512*, falcon1024*
    * SPHINCS-SHA2:sphincssha2128fsimple*, sphincssha2128ssimple*, sphincssha2192fsimple*, sphincssha2192ssimple, sphincssha2256fsimple, sphincssha2256ssimple
    * SPHINCS-SHAKE:sphincsshake128fsimple*, sphincsshake128ssimple, sphincsshake192fsimple, sphincsshake192ssimple, sphincsshake256fsimple, sphincsshake256ssimple

The client-side implementation has been carried out using the Docker curl image made by OQS, obtaining a quantum-safe client program.

## Steps
### 1. Docker Engine installation (Ubuntu)
    apt  install docker.io
### 2. Quantum-Safe Nginx Server installation (Ubuntu)
    docker pull openquantumsafe/nginx
### 3. Reverse Proxy configuration (Ubuntu)
To perform the Nginx server as a reverse proxy, it is necessary to specify the configuration using the file "nginx.conf", and in turn specify the PQC keys with which the authentication of the communication is going to be performed.
Structure of the configuration file, "nginx.cnf":

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

                ssl_certificate      /opt/nginx/pki/nginx-server.crt;
                ssl_certificate_key  /opt/nginx/pki/nginx-server.key;

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

These configuration files set the reverse proxy setting, recive HTTPS requests with PQC certificates and redirecting these to the desired service using traditional HTTPS.
The key parameters to take into account:
* __Proxy's listening ports:__ Specify the port on which the server will listen for incoming requests, to which the client using the curl command must communicate.
* __Path to the PQC certificates:__ The section __ssl_certificate__ and __ssl_certificate_key__  specify the exactly root where PQC certificates and keys shall be stored. If those certificates and keys are to be generated outside of the Docker image, recommended implementation, it should be generated a virtual link (Docker's volume) that points: the local certificate's folder to the one that listen the Docker image "/opt/nginx/pki/".
* __Especificación del método KEM:__ The section __ssl_ecdh_curve__ shall be specified the KEM algorithm (PQC) through which the handshake is to be established. Some of the available methods are: frodo976shake:frodo1344shake:p256_kyber512:kyber768:kyber1024:kyber512
* __Location:__ The section "location" alognside "/" it must be specified the address where Nginx shall handle requests, in other words, any regular expression that matches the specified expression will be processed by nginx. That request will be resended to the direction and ports specified into __proxy_pas__. That proxy pass will be made based on SSL/TLS traditional protocol, whose keys are specified as the parameters __proxy_ssl_certificate__ y __proxy_ssl_certificate_key__. 

### 4. PQC key generator script (Ubuntu)
As mentioned previously, two types of keys shall be generated: PQC keysto authenticate quantum-safe HTTPS communication with the outside, and traditional keys to authenticate the communication with the final server.
It is recommended the key generation via command line "openssl", as an example:

    openssl req -x509 -new -newkey falcon1024 -keyout ca.key -out ca.crt -nodes  -subj "XXX" -days 3650 -config $openssl_conf

    openssl genpkey -algorithm falcon1024 -out nginx-server.key
    openssl req -new -key nginx-server.key -out nginx-server-csr.pem -nodes -config $openssl_conf
    openssl x509 -req -in nginx-server-csr.pem -CA ca.crt -CAkey ca.key -CAcreateserial -out nginx-server.crt -days 365

### 5. PQC Curl installation (Ubuntu)
    docker pull openquantumsafe/curl

### 6. Communication establishment (Ubuntu)
It should be noted that the self-signing certificate implemented for the generation of PQC keys in the reverse proxy, must be available in the virtual machine that will work as a client.

In turn, as mentioned, in order to be able to configure and work persistently with the specifications defined in the "nginx.cnf" file, volumes must be established. When the container is started openquantumsafe/nginx and openquantumsafe/curl with the link __-v__ /host/root:/container/root, allows to create the specific directory of the host inside the container.

Docker's container started commands:

#### Proxy
    docker run -p <Puerto de Escucha>:<Puerto de Escucha> -v "/ruta/en/host/nginx-conf:/opt/nginx/nginx-conf" -v "/ruta/en/host/server-pki:/opt/nginx/pki" openquantumsafe/nginx

#### Client
    docker run -v "/ruta/en/host/ca.crt:/etc/ssl/certs/ca.crt" -it openquantumsafe/curl curl --cacert /etc/ssl/certs/ca.crt -X GET https://IP_VM:PORT_VM/ENDPOINT
