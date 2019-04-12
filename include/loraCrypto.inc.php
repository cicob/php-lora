<?php

/********************************************************************************************************************************

    The Open Source Initiative --  BSD 2-Clause License
 
	Copyright (c) 2016, Christer Boberg
	All rights reserved.
	
	Redistribution and use in source and binary forms, with or without modification, are permitted 
	provided that the following conditions are met:
	
	1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
	
	2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following 
	   disclaimer in the documentation and/or other materials provided with the distribution.
	
	THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, 
	BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT 
	SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL 
	DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
	INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE 
	OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


 ********************************************************************************************************************************/
 


/**
 * Constructor sets the key and the device address
 * 
 * @param
 *        	key: 16-byte hex-encoded AES key. (i.e. AABBCCDDEEFFAABBCCDDEEFFAABBCCDD)
 * @param
 *        	dev_addr: 4-byte hex-encoded DevAddr (i.e. AABBCCDD)
 *        	
 */
class loraCrypto {
	public function __construct($key_hex, $dev_addr_hex) {
		$this->key_hex = $key_hex;
		$this->dev_addr_hex = $dev_addr_hex;
	}
	function setKey($key_hex) {
		$this->key_hex = $key_hex;
		return 0;
	}
	function setDevAddr($dev_addr_hex) {
		$this->dev_addr_hex = $dev_addr_hex;
		return 0;
	}
	
	/**
	 * LoraMac decrypt, which is actually encrypting each 16-byte block and XORing
	 * that with each block of data.
	 *
	 * This method is based on `loramac_decrypt()` written in Python here
	 * https://github.com/jieter/python-lora/blob/master/lora/crypto.py
	 * ...which in turn is based on `LoRaMacPayloadEncrypt()` by Semtech in
	 * https://github.com/Lora-net/LoRaMac-node/blob/master/src/mac/LoRaMacCrypto.c#L108
	 *
	 * @param
	 *        	payload_hex: hex-encoded payload encrypted
	 * @param
	 *        	sequence_counter_dec: integer, sequence counter (FCntUp)
	 * @param
	 *        	direction: 0 for uplink packets, 1 for downlink packets (Optional)
	 * @return an array of byte values, decrypted
	 *        
	 */
	function decrypt($payload_hex, $sequence_counter_dec, $direction_dec = 0) {
		$buffer = pack ( "H*", $payload_hex );
		$size = strlen ( $buffer );
		$sequence_counter = pack ( "H*", sprintf ( "%08X", $sequence_counter_dec ) );
		$key = pack ( "H*", $this->key_hex );
		$dev_addr = pack ( "H*", $this->dev_addr_hex );
		$direction = pack ( "H*", sprintf ( "%08X", $direction_dec ) );
		
		$bufferIndex = 0;
		$ctr = 1;
		
		// output buffer, initialize to input buffer size.
		$encBuffer = str_pad ( "", $size, "\x00" );
		
		// For the exact definition of this block '$aBlock' refer to
		// 'chapter 4.3.3.1 Encryption in LoRaWAN' in the LoRaWAN specification
		
		$aBlock = str_pad ( "", 16, "\x00" );
		$aBlock [0] = "\x01"; // 0 always 0x01
		$aBlock [1] = "\x00"; // 1 always 0x00
		$aBlock [2] = "\x00"; // 2 always 0x00
		$aBlock [3] = "\x00"; // 3 always 0x00
		$aBlock [4] = "\x00"; // 4 always 0x00
		$aBlock [5] = $direction; // 5 dir, 0 for uplink, 1 for downlink
		
		$aBlock [6] = $dev_addr [3]; // 6 devaddr, lsb
		$aBlock [7] = $dev_addr [2]; // 7 devaddr
		$aBlock [8] = $dev_addr [1]; // 8 devaddr
		$aBlock [9] = $dev_addr [0]; // 9 devaddr, msb
		
		$aBlock [10] = $sequence_counter [3]; // 10 sequence counter (FCntUp) lsb
		$aBlock [11] = $sequence_counter [2]; // 11 sequence counter
		$aBlock [12] = $sequence_counter [1]; // 12 sequence counter
		$aBlock [13] = $sequence_counter [0]; // 13 sequence counter (FCntUp) msb
		$aBlock [14] = "\x00"; // 14 always 0x00 not 0x01
		$aBlock [15] = "\x00"; // 15 block counter
		                     
		// complete blocks
		while ( $size >= 16 ) {
			$aBlock [15] = "\x01"; // = $ctr initial value
			$ctr += 1;
			$sBlock = mcrypt_encrypt ( MCRYPT_RIJNDAEL_128, $key, $aBlock, MCRYPT_MODE_ECB );
			for($i = 0; $i < 16; $i ++) {
				$encBuffer [$bufferIndex + $i] = $buffer [$bufferIndex + $i] ^ $sBlock [$i];
			}
			$size -= 16;
			$bufferIndex += 16;
		}
		
		// partial blocks
		if ($size > 0) {
			$aBlock [15] = pack ( "C", $ctr );
			$sBlock = mcrypt_encrypt ( MCRYPT_RIJNDAEL_128, $key, $aBlock, MCRYPT_MODE_ECB );
			for($i = 0; $i < $size; $i ++) {
				$encBuffer [$bufferIndex + $i] = $buffer [$bufferIndex + $i] ^ $sBlock [$i];
			}
		}
		
		return bin2hex ( $encBuffer );
	} // end method
} // end class
  
// Important! No extra white-space or linefeed after next line!!!
?>