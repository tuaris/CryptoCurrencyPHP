<?php
/* 
 * Crypto Currency Wallet
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
 * @author Daniel Morante
 * Some parts may contain work based on Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt
*/

class Wallet{

	private $PRIVATE_KEY;
	private $MESSAGE_MAGIC;
	private $NETWORK_PREFIX;
	private $NETWORK_NAME;

	public function __construct(PrivateKey $private_key = null, $networkPrefix = '00', $networkName = 'Bitcoin', $messageMagic = null){
		// Private key
		if(!empty($private_key)){
			$this->PRIVATE_KEY = $private_key;
		}

		// The prefix, network name, and message magic
		$this->setNetworkPrefix($networkPrefix);
		$this->setNetworkName($networkName);
		$this->setMessageMagic($messageMagic);
	}

    /***
     * Set the network prefix, '00' = main network, '6f' = test network.
     *
     * @param String Hex $prefix
     */
    public function setNetworkPrefix($prefix){
		// The prefix
		if(!empty($prefix)){
			$this->NETWORK_PREFIX = $prefix;
		}
    }

    /**
     * Returns the current network prefix, '00' = main network, '6f' = test network.
     *
     * @return String Hex
     */
    public function getNetworkPrefix(){
        return $this->NETWORK_PREFIX;
    }

    /***
     * Set the network name
     *
     * @param String $name
     */
    public function setNetworkName($name){
		// The network name
		if(!empty($name)){
			$this->NETWORK_NAME = $name;
		}
    }

    /**
     * Returns the current network name
     *
     * @return String
     */
    public function getNetworkName(){
        return $this->NETWORK_NAME;
    }

    /***
     * Set the magic message prefix
     *
     * @param String $magic
     */
    public function setMessageMagic($magic){
		// The signed message "magic" prefix.
			$this->MESSAGE_MAGIC = $magic;
    }

    /**
     * Returns the current magic message prefix
     *
     * @return String
     */
    public function getMessageMagic(){
		// Check if a custom messageMagic is being used
		if(!empty($this->MESSAGE_MAGIC)){
			// Use the custom one.
			$magic = $this->MESSAGE_MAGIC;
		}
		else{
			// Use the default which is: "[LINE_LEN] [NETWORK_NAME] Signed Message:\n"
			$default = $this->getNetworkName() . " Signed Message:\n";
			$magic = $this->numToVarIntString(strlen($default)) . $default;
		}
        return $magic;
    }

    /***
     * returns the compressed Bitcoin address generated from the private key.
     *
     * @param string $derPubKey
     * @return String Base58
     */
    public function getAddress(){
		$PubKeyPoints = $this->getPrivateKey()->getPubKeyPoints();
		$DERPubkey = AddressCodec::Compress($PubKeyPoints);
        return AddressCodec::Encode(AddressCodec::Hash($DERPubkey), $this->getNetworkPrefix());
    }
	
	public function getUncompressedAddress(){
		$PubKeyPoints = $this->getPrivateKey()->getPubKeyPoints();
		return AddressCodec::Hex(AddressCodec::Hash($PubKeyPoints));
	}

	private function getPrivateKey(){
		if(empty($this->PRIVATE_KEY)){
			throw new \Exception('Wallet does not have a private key');
		}
		else{
			return $this->PRIVATE_KEY;
		}
	}

    /***
     * Satoshi client's standard message signature implementation.
     *
     * @param $message
     * @param bool $compressed
     * @param null $nonce
     * @return string
     * @throws \Exception
     */
    public function signMessage($message, $compressed = true, $nonce = null)
    {

        $hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)). $message);
        $points = Signature::getSignatureHashPoints(
                                                $hash,
												$this->getPrivateKey()->getPrivateKey(),
                                                $nonce
                   );

        $R = $points['R'];
        $S = $points['S'];

        while(strlen($R) < 64)
            $R = '0' . $R;

        while(strlen($S) < 64)
            $S = '0' . $S;

        $res = "\n-----BEGIN " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----\n";
        $res .= $message;
        $res .= "\n-----BEGIN SIGNATURE-----\n";
        if(true == $compressed)
            $res .= $this->getAddress() . "\n";
        else
            $res .= $this->getUncompressedAddress() . "\n";

        $finalFlag = 0;
        for($i = 0; $i < 4; $i++)
        {
            $flag = 27;
            if(true == $compressed)
                $flag += 4;
            $flag += $i;

            $pubKeyPts =$this->getPrivateKey()->getPubKeyPoints();
            //echo "\nReal pubKey : \n";
            //print_r($pubKeyPts);

            $recoveredPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
            //echo "\nRecovered PubKey : \n";
            //print_r($recoveredPubKey);

            if(AddressCodec::Compress($pubKeyPts) == $recoveredPubKey)
            {
                $finalFlag = $flag;
            }
        }

        //echo "Final flag : " . dechex($finalFlag) . "\n";
        if(0 == $finalFlag)
        {
            throw new \Exception('Unable to get a valid signature flag.');
        }


        $res .= base64_encode(hex2bin(dechex($finalFlag) . $R . $S));
        $res .= "\n-----END " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----";

        return $res;
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $rawMessage
     * @return bool
     */
    public function checkSignatureForRawMessage($rawMessage)
    {
        //recover message.
        preg_match_all("#-----BEGIN " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----\n(.{0,})\n-----BEGIN SIGNATURE-----\n#USi", $rawMessage, $out);
        $message = $out[1][0];

        preg_match_all("#\n-----BEGIN SIGNATURE-----\n(.{0,})\n(.{0,})\n-----END " . strtoupper($this->getNetworkName()) . " SIGNED MESSAGE-----#USi", $rawMessage, $out);
        $address = $out[1][0];
        $signature = $out[2][0];

		// Alternate version
        //return $this->checkSignedMessage($address, $signature, $message);
        return $this->checkSignatureForMessage($address, $signature, $message);
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $address String
     * @param $encodedSignature String
     * @param $message String
     * @return bool
     */
    public function checkSignatureForMessage($address, $encodedSignature, $message)
    {
        // $hash is HEX String
		$hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)) . $message);

        //recover flag

		// $signature is BIN
        $signature = base64_decode($encodedSignature);

		// $flag is INT
        $flag = hexdec(bin2hex(substr($signature, 0, 1)));

		// Convert BIN to HEX String
        $R = bin2hex(substr($signature, 1, 32));
        $S = bin2hex(substr($signature, 33));

        $derPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($derPubKey), $this->getNetworkPrefix());

		/* Alternate version
		$pubkeyPoint = Signature::recoverPublicKey_HEX($flag, $R, $S, $hash);
		$recoveredAddress = AddressCodec::Encode(AddressCodec::Hash(AddressCodec::Compress($pubkeyPoint)), $this->getNetworkPrefix());
		*/

        if($address == $recoveredAddress)
            return true;
        else
            return false;
    }
	
	// Same as above - But not working correctly
	// All Paramaters are Strings
	public function checkSignedMessage($address, $encodedSignature, $message){
		// $signature is BIN
		$signature = base64_decode($encodedSignature, true);

		// $recoveryFlags is INT
		$recoveryFlags = ord($signature[0]) - 27;

		if ($recoveryFlags < 0 || $recoveryFlags > 7) {
			throw new InvalidArgumentException('invalid signature type');
		}

		// $isCompressed is BOOL
		$isCompressed = ($recoveryFlags & 4) != 0;

		// $hash is HEX String
		$hash = $this->hash256($this->getMessageMagic() . $this->numToVarIntString(strlen($message)) . $message);

		// Convert BIN to HEX String
        $R = gmp_init(bin2hex(substr($signature, 1, 32)), 16);
        $S = gmp_init(bin2hex(substr($signature, 33)), 16);

		$hash = gmp_init($hash, 16);

		// $pubkey is Array(HEX String, HEX String)
		$pubkeyPoint = Signature::recoverPublicKey($R, $S, $hash, $recoveryFlags);

		if ($isCompressed) {
			$recoveredAddress = AddressCodec::Compress($pubkeyPoint);
		}
		else{
			$recoveredAddress = AddressCodec::Hex($pubkeyPoint);
		}

		$recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($recoveredAddress), $this->getNetworkPrefix());
		return $address === $recoveredAddress;
	}
	
	/***
	 * Standard 256 bit hash function : double sha256
	 *
	 * @param $data
	 * @return string
	 */
	private function hash256($data){
		return hash('sha256', hex2bin(hash('sha256', $data)));
	}
	
    /***
     * Convert a number to a compact Int
     * taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/verifymessage.php
     *
     * @param $i
     * @return string
     * @throws \Exception
     */
    private function numToVarIntString($i) {
        if ($i < 0xfd) {
            return chr($i);
        } else if ($i <= 0xffff) {
            return pack('Cv', 0xfd, $i);
        } else if ($i <= 0xffffffff) {
            return pack('CV', 0xfe, $i);
        } else {
            throw new \Exception('int too large');
        }
    }
}
?>
