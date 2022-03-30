Generate private-public RSA key pair:

```
openssl genrsa -out testdata/oauth/87329db33bf_pri.pem 4096
openssl rsa -in testdata/oauth/87329db33bf_pri.pem -pubout -out testdata/oauth/87329db33bf_pub.pem
```
