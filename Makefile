#

all:: eckey-pub.pem eckey-priv.pem

eckey-pair.pem:
	openssl ecparam -genkey -name secp128r1 -out $@

eckey-pub.pem: eckey-pair.pem
	openssl ec -in $< -outform PEM -pubout -out $@

eckey-priv.pem: eckey-pair.pem
	openssl ec -in $< -outform PEM -out $@

clean::
	@rm -f eckey-*.pem
