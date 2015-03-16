<?php
/* 
 * Crypto Currency Wallet
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
 * @author Daniel Morante
 * Some parts may contain work based on Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt
*/

class Wallet{

	private $PRIVATE_KEY;
	private $PREFIX;
	private $NETWORK;

	public function __construct(PrivateKey $private_key, $networkPrefix = '00', $networkName = 'Bitcoin'){
		// Private key
		if(empty($private_key)){
			throw new \Exception('Wallet requires a private key');
		}
		else{
			$this->PRIVATE_KEY = $private_key;
		}

		// The prefix and network name
		$this->setNetworkPrefix($networkPrefix);
		$this->setNetworkName($networkName);
	}

    /***
     * Set the network prefix, '00' = main network, '6f' = test network.
     *
     * @param String Hex $prefix
     */
    public function setNetworkPrefix($prefix){
		// The prefix
		if(!empty($prefix)){
			$this->PREFIX = $prefix;
		}
    }

    /**
     * Returns the current network prefix, '00' = main network, '6f' = test network.
     *
     * @return String Hex
     */
    public function getNetworkPrefix(){
        return $this->PREFIX;
    }

    /***
     * Set the network name
     *
     * @param String Hex $name
     */
    public function setNetworkName($name){
		// The network name
		if(!empty($name)){
			$this->NETWORK = $name;
		}
    }

    /**
     * Returns the current network name
     *
     * @return String
     */
    public function getNetworkName(){
        return $this->NETWORK;
    }

    /***
     * returns the compressed Bitcoin address generated from the private key.
     *
     * @param string $derPubKey
     * @return String Base58
     */
    public function getAddress(){
		$PubKeyPoints = $this->PRIVATE_KEY->getPubKeyPoints();
		$DERPubkey = AddressCodec::Compress($PubKeyPoints);
        return AddressCodec::Encode(AddressCodec::Hash($DERPubkey), $this->PREFIX);
    }
	
	public function getUncompressedAddress(){
		$PubKeyPoints = $this->PRIVATE_KEY->getPubKeyPoints();
		return AddressCodec::Hex(AddressCodec::Hash($PubKeyPoints));
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

        $hash = $this->hash256("\x18" . $this->NETWORK . " Signed Message:\n" . $this->numToVarIntString(strlen($message)). $message);
        $points = Signature::getSignatureHashPoints(
                                                $hash,
												$this->PRIVATE_KEY->getPrivateKey(),
                                                $nonce
                   );

        $R = $points['R'];
        $S = $points['S'];

        while(strlen($R) < 64)
            $R = '0' . $R;

        while(strlen($S) < 64)
            $S = '0' . $S;

        $res = "\n-----BEGIN " . strtoupper($this->NETWORK) . " SIGNED MESSAGE-----\n";
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

            $pubKeyPts =$this->PRIVATE_KEY->getPubKeyPoints();
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
        $res .= "\n-----END " . strtoupper($this->NETWORK) . " SIGNED MESSAGE-----";

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
        preg_match_all("#-----BEGIN " . strtoupper($this->NETWORK) . " SIGNED MESSAGE-----\n(.{0,})\n-----BEGIN SIGNATURE-----\n#USi", $rawMessage, $out);
        $message = $out[1][0];

        preg_match_all("#\n-----BEGIN SIGNATURE-----\n(.{0,})\n(.{0,})\n-----END " . strtoupper($this->NETWORK) . " SIGNED MESSAGE-----#USi", $rawMessage, $out);
        $address = $out[1][0];
        $signature = $out[2][0];

        return $this->checkSignatureForMessage($address, $signature, $message);
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $address
     * @param $encodedSignature
     * @param $message
     * @return bool
     */
    public function checkSignatureForMessage($address, $encodedSignature, $message)
    {
        $hash = $this->hash256("\x18" . $this->NETWORK . " Signed Message:\n" . $this->numToVarIntString(strlen($message)) . $message);


        //recover flag
        $signature = base64_decode($encodedSignature);

        $flag = hexdec(bin2hex(substr($signature, 0, 1)));

        $R = bin2hex(substr($signature, 1, 64));
        $S = bin2hex(substr($signature, 65, 64));

        $derPubKey = Signature::getPubKeyWithRS($flag, $R, $S, $hash);
		FB::log($derPubKey);
        $recoveredAddress = AddressCodec::Encode(AddressCodec::Hash($derPubKey));

        if($address == $recoveredAddress)
            return true;
        else
            return false;
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
