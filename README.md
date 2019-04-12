# PHP LoRa
PHP-implementation of a LoRa-payload decryption

LoraMac decrypt, which is actually encrypting each 16-byte block and XORing that with each block of data.
	 
This method is based on `loramac_decrypt()` written in Python here
<https://github.com/jieter/python-lora/blob/master/lora/crypto.py>

...which in turn is based on `LoRaMacPayloadEncrypt()` by Semtech in
<https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/LoRaMacCrypto.c#L108>


   
