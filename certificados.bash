cd certs
# Genera certificado y clave (RSA 4096)
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout server.key -out server.crt -subj "/C=ES/ST=Sevilla/L=Sevilla/O=Uni/OU=TFG/CN=localhost"