<?php


//  Run test from the VM-terminal
//
//     /vagrant/shared/lora/include/vendor/bin/phpunit /vagrant/shared/lora/include/loraCryptoTest.inc.php
//



//require_once($_SERVER['DOCUMENT_ROOT']."/stub.inc.php");
static $root = "/vagrant/shared/lora/include";
require_once ($root . "/loraCrypto.inc.php");

class loraCryptoTest extends PHPUnit_Framework_TestCase {	
	
	/*-
				https://github.com/jieter/python-lora/blob/master/tests/14000122.txt	
	
	 # XMLs provided by KPN on 2016-03-25
	 # devAddr: 14000122
	 # key: C6FB9E3C87AC393B43174EFA8F832195
	 # transmissions on port 1 are plaintext, port 2 are encrypted.
	
	 */	
	public function testDectrypt() {
			
		$expectation = array(
				"0b", 
				"0a", 
				"4321", 
				"1234", 
				"54321", 
				"12345", 
				"012345",
				"654321", 
				"123456", 
				"0123456789abcdef4321",
				"0123456789abcdef1234",
				"00123456789abcdef54321",
				"00123456789abcdef12345",
				"0123456789abcdef654321",
				"0123456789abcdef0123456789abcdef",		 
				"0123456789abcdef0123456789abcdef"		
		);
		
		$xml = array(
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:10:29.588+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>82</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>88</FCntDn><payload_hex>c8</payload_hex><mic_hex>21f624d0</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.000000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC1</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.000000</LrrSNR><LrrESP>-28.413927</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",		
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:10:44.288+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>84</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>90</FCntDn><payload_hex>95</payload_hex><mic_hex>5c4e5158</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.250000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC1</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.250000</LrrSNR><LrrESP>-27.605556</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",		
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:10:56.805+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>86</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>92</FCntDn><payload_hex>a167</payload_hex><mic_hex>b1f629fc</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.500000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC3</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.500000</LrrSNR><LrrESP>-27.573822</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",		
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:11:09.660+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>88</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>94</FCntDn><payload_hex>5c74</payload_hex><mic_hex>141f79e2</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>9.750000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC1</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>9.750000</LrrSNR><LrrESP>-28.437258</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:11:22.472+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>90</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>96</FCntDn><payload_hex>72c727</payload_hex><mic_hex>ed898137</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-23.000000</LrrRSSI><LrrSNR>8.750000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC2</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-23.000000</LrrRSSI><LrrSNR>8.750000</LrrSNR><LrrESP>-23.543650</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:11:42.518+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>92</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>98</FCntDn><payload_hex>58ba24</payload_hex><mic_hex>426aa579</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.000000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC2</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.000000</LrrSNR><LrrESP>-27.638920</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:12:04.689+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>94</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>100</FCntDn><payload_hex>835db5</payload_hex><mic_hex>e3e0affa</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-29.000000</LrrRSSI><LrrSNR>9.750000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC3</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-29.000000</LrrRSSI><LrrSNR>9.750000</LrrSNR><LrrESP>-29.437258</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:12:18.343+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>96</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>102</FCntDn><payload_hex>30af33</payload_hex><mic_hex>3569a29a</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.000000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC1</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.000000</LrrSNR><LrrESP>-28.413927</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:12:35.368+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>98</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>104</FCntDn><payload_hex>eb496e</payload_hex><mic_hex>ab990d15</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.750000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC3</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.750000</LrrSNR><LrrESP>-28.350851</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:12:48.152+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>100</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>106</FCntDn><payload_hex>551edc7c807aa97e0efc</payload_hex><mic_hex>0bb0327d</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.250000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC1</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>8.250000</LrrSNR><LrrESP>-27.605556</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:13:01.155+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>102</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>108</FCntDn><payload_hex>33500e0201fd25456c40</payload_hex><mic_hex>6d3f06ce</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.500000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC2</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.500000</LrrSNR><LrrESP>-28.370777</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:13:13.852+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>104</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>110</FCntDn><payload_hex>67f93000c6f907e477a0d7</payload_hex><mic_hex>7693f5f0</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-29.000000</LrrRSSI><LrrSNR>10.500000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC3</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-29.000000</LrrRSSI><LrrSNR>10.500000</LrrSNR><LrrESP>-29.370777</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",	
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:13:42.124+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>106</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>112</FCntDn><payload_hex>b8060d0f29499ca3081915</payload_hex><mic_hex>2569a925</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>9.000000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC2</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-27.000000</LrrRSSI><LrrSNR>9.000000</LrrSNR><LrrESP>-27.514969</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:13:56.25+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>108</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>114</FCntDn><payload_hex>47aeb5c4712c63e9197fd5</payload_hex><mic_hex>2b53deee</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-29.000000</LrrRSSI><LrrSNR>9.000000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC3</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070278</LrrLAT><LrrLON>4.478838</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-29.000000</LrrRSSI><LrrSNR>9.000000</LrrSNR><LrrESP>-29.514969</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",		
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:33:54.280+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>110</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>117</FCntDn><payload_hex>15c8d5678b86edb5349b89b57da71cb8</payload_hex><mic_hex>5b23d6c6</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.250000</LrrSNR><SpFact>8</SpFact><SubBand>G1</SubBand><Channel>LC2</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070332</LrrLAT><LrrLON>4.478900</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.250000</LrrSNR><LrrESP>-28.391785</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>",				
				"<?xml version=\"1.0\" encoding=\"UTF-8\"?><DevEUI_uplink xmlns=\"http://uri.actility.com/lora\"><Time>2016-03-25T14:34:05.369+01:00</Time><DevEUI>0059AC0000100222</DevEUI><FPort>2</FPort><FCntUp>112</FCntUp><ADRbit>1</ADRbit><MType>4</MType><FCntDn>119</FCntDn><payload_hex>c7d9853a545d9789a5e4285c0859d6fb</payload_hex><mic_hex>6e59af9f</mic_hex><Lrcid>0059AC01</Lrcid><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.000000</LrrSNR><SpFact>7</SpFact><SubBand>G1</SubBand><Channel>LC3</Channel><DevLrrCnt>1</DevLrrCnt><Lrrid>08050042</Lrrid><LrrLAT>52.070332</LrrLAT><LrrLON>4.478900</LrrLON><Lrrs><Lrr><Lrrid>08050042</Lrrid><Chain>0</Chain><LrrRSSI>-28.000000</LrrRSSI><LrrSNR>10.000000</LrrSNR><LrrESP>-28.413927</LrrESP></Lrr></Lrrs><CustomerID>100006246</CustomerID><CustomerData>{\"alr\":{\"pro\":\"SMTC/LoRaMote\",\"ver\":\"1\"}}</CustomerData><ModelCfg>0</ModelCfg></DevEUI_uplink>"		
		);

				
		$loraCrypto = new loraCrypto("C6FB9E3C87AC393B43174EFA8F832195", "14000122");
		
		for ($i = 0; $i < 16; $i++) {
			$xmlString = simplexml_load_string($xml[$i]);
			$this->assertEquals( $expectation[$i], 
					$loraCrypto->decrypt($xmlString->payload_hex, $xmlString->FCntUp) 

					);

		
		}
	
	} // end function/method
} // end class


?>