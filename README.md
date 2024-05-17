# Desciption

For test generate jwt with public and private key with ecdsa


## Use open ssl create private and public key

openssl ecparam -name prime256v1 -genkey -noout -out ec_private.pem

openssl ec -in ec_private.pem -pubout -out ec_public.pem

## Change EC PRIVATE KEY to PRIVATE KEY

openssl pkcs8 -topk8 -nocrypt -in ec_private.pem -out private_key_pkcs8.pem!

