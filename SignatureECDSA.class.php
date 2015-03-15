<?php

/**
 *
 * @author Daniel Morante
 * Based on work by Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt
 */

class secp256k1Signature {

    public $k;
    public $a;
    public $b;
    public $p;
    public $n;
    public $G;

    public function __construct()
    {
        $this->a = gmp_init('0', 10);
        $this->b = gmp_init('7', 10);
        $this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        $this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

        $this->G = array('x' => gmp_init('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
                         'y' => gmp_init('32670510020758816978083085130507043184471273380659243275938904335757337482424'));

        
    }

	// Simple Wrappers
	private function calculateYWithX($x, $derEvenOrOddCode = null){
		return MathECDSA::calculateYWithX($x, $this->a, $this->b, $this-p, $derEvenOrOddCode);
	}
	private function mulPoint($k, Array $pG, $base = null){
		return MathECDSA::mulPoint($k, $pG, $this->a, $this->b, $this->p, $base);
	}
	private function addPoints(Array $pt1, Array $pt2){
		return MathECDSA::addPoints($pt1, $pt2, $this->a, $this->p);
	}

	private function getUncompressedAddress($compressed = false, $derPubKey = null){
		if(null != $derPubKey){
			$address = $derPubKey;
		}
		else{
			if($compressed) {
				$address = $this->getPubKey();
			}
			else {
				$address = $this->getUncompressedPubKey();
			}
		}
		return AddressCodec::uncompressedAddress($address);
	}

    /***
     * Convert a number to a compact Int
     * taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/verifymessage.php
     *
     * @param $i
     * @return string
     * @throws \Exception
     */
    public static function numToVarIntString($i) {
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

	/***
	 * Standard 256 bit hash function : double sha256
	 *
	 * @param $data
	 * @return string
	 */
	public function hash256($data){
		return hash('sha256', hex2bin(hash('sha256', $data)));
	}

    public function getDerPubKeyWithPubKeyPoints($pubKey, $compressed = true)
    {
        if(true == $compressed)
        {
            return '04' . $pubKey['x'] . $pubKey['y'];
        }
        else
        {
            return AddressCodec::CompressPubKey($pubKey);
        }
    }


    public function getPubKeyPoints(){
		return $this->PubKeyPoints;
	}


    /***
     * returns the uncompressed DER encoded public key.
     *
     * @return String Hex
     */
    public function getUncompressedPubKey()
    {
        $pubKey			    = $this->getPubKeyPoints();
        $uncompressedPubKey	= '04' . $pubKey['x'] . $pubKey['y'];

        return $uncompressedPubKey;
    }


    /***
     * returns the compressed DER encoded public key.
     *
     * @return String Hex
     */
    public function getPubKey()
    {
        return AddressCodec::EncodePubKey($this->getPubKeyPoints());
    }

    /***
     * returns the compressed Bitcoin address generated from the private key.
     *
     * @param string $derPubKey
     * @return String Base58
     */
    public function getAddress($derPubKey = null)
    {
        return $this->getUncompressedAddress(true, $derPubKey);
    }


    /***
     * Sign a hash with the private key that was set and returns signatures as an array (R,S)
     *
     * @param $hash
     * @param null $nonce
     * @throws \Exception
     * @return Array
     */
    public function getSignatureHashPoints($hash, $nonce = null)
    {
        $n = $this->n;
        $k = $this->k;

        if(empty($k))
        {
            throw new \Exception('No Private Key was defined');
        }

        if(null == $nonce)
        {
            $random     = openssl_random_pseudo_bytes(256, $cStrong);
            $random     = $random . microtime(true).rand(100000000000, 1000000000000);
            $nonce      = gmp_strval(gmp_mod(gmp_init(hash('sha256',$random), 16), $n), 16);
        }

        //first part of the signature (R).

        $rPt = $this->mulPoint($nonce, $this->G);
        $R	= gmp_strval($rPt ['x'], 16);

        while(strlen($R) < 64)
        {
            $R = '0' . $R;
        }

        //second part of the signature (S).
        //S = nonce^-1 (hash + privKey * R) mod p

        $S = gmp_strval(
                        gmp_mod(
                                gmp_mul(
                                        gmp_invert(
                                                   gmp_init($nonce, 16),
                                                   $n
                                        ),
                                        gmp_add(
                                                gmp_init($hash, 16),
                                                gmp_mul(
                                                        gmp_init($k, 16),
                                                        gmp_init($R, 16)
                                                )
                                        )
                                ),
                                $n
                        ),
                        16
             );

        if(strlen($S)%2)
        {
            $S = '0' . $S;
        }

        if(strlen($R)%2)
        {
            $R = '0' . $R;
        }

        return array('R' => $R, 'S' => $S);
    }

    /***
     * Sign a hash with the private key that was set and returns a DER encoded signature
     *
     * @param $hash
     * @param null $nonce
     * @return string
     */
    public function signHash($hash, $nonce = null)
    {
        $points = $this->getSignatureHashPoints($hash, $nonce);

        $signature = '02' . dechex(strlen(hex2bin($points['R']))) . $points['R'] . '02' . dechex(strlen(hex2bin($points['S']))) . $points['S'];
        $signature = '30' . dechex(strlen(hex2bin($signature))) . $signature;

        return $signature;
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

        $hash = $this->hash256("\x18Bitcoin Signed Message:\n" . $this->numToVarIntString(strlen($message)). $message);
        $points = $this->getSignatureHashPoints(
                                                $hash,
                                                $nonce
                   );

        $R = $points['R'];
        $S = $points['S'];

        while(strlen($R) < 64)
            $R = '0' . $R;

        while(strlen($S) < 64)
            $S = '0' . $S;

        $res = "\n-----BEGIN BITCOIN SIGNED MESSAGE-----\n";
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

            $pubKeyPts = $this->getPubKeyPoints();
            //echo "\nReal pubKey : \n";
            //print_r($pubKeyPts);

            $recoveredPubKey = $this->getPubKeyWithRS($flag, $R, $S, $hash);
            //echo "\nRecovered PubKey : \n";
            //print_r($recoveredPubKey);

            if($this->getDerPubKeyWithPubKeyPoints($pubKeyPts, $compressed) == $recoveredPubKey)
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
        $res .= "\n-----END BITCOIN SIGNED MESSAGE-----";

        return $res;
    }

    /***
     * extract the public key from the signature and using the recovery flag.
     * see http://crypto.stackexchange.com/a/18106/10927
     * based on https://github.com/brainwallet/brainwallet.github.io/blob/master/js/bitcoinsig.js
     * possible public keys are r−1(sR−zG) and r−1(sR′−zG)
     * Recovery flag rules are :
     * binary number between 28 and 35 inclusive
     * if the flag is > 30 then the address is compressed.
     *
     * @param $flag
     * @param $R
     * @param $S
     * @param $hash
     * @return array
     */
    public function getPubKeyWithRS($flag, $R, $S, $hash)
    {


        $isCompressed = false;

        if ($flag < 27 || $flag >= 35)
            return false;

        if($flag >= 31) //if address is compressed
        {
            $isCompressed = true;
            $flag -= 4;
        }

        $recid = $flag - 27;


        //step 1.1
        $x = null;
        $x = gmp_add(
                     gmp_init($R, 16),
                     gmp_mul(
                             $this->n,
                             gmp_div_q( //check if j is equal to 0 or to 1.
                                        gmp_init($recid, 10),
                                        gmp_init(2, 10)
                             )
                     )
             );



        //step 1.3
        $y = null;
        if(1 == $flag % 2) //check if y is even.
        {

            $gmpY = $this->calculateYWithX(gmp_strval($x, 16), '02');

            if(null != $gmpY)

                $y = gmp_init($gmpY, 16);

        }
        else
        {

            $gmpY = $this->calculateYWithX(gmp_strval($x, 16), '03');
            if(null != $gmpY)
                $y = gmp_init($gmpY, 16);
        }


        if(null == $y)
            return null;

        $Rpt = array('x' => $x, 'y' => $y);

        //step 1.6.1
        //calculate r^-1 (S*Rpt - eG)

        $eG = $this->mulPoint($hash, $this->G);

        $eG['y'] = gmp_mod(gmp_neg($eG['y']), $this->p);

        $SR = $this->mulPoint($S, $Rpt);

        $pubKey = $this->mulPoint(
                            gmp_strval(gmp_invert(gmp_init($R, 16), $this->n), 16),
                            $this->addPoints(
                                             $SR,
                                             $eG
                            )
                  );


        $pubKey['x'] = gmp_strval($pubKey['x'], 16);
        $pubKey['y'] = gmp_strval($pubKey['y'], 16);

        while(strlen($pubKey['x']) < 64)
            $pubKey['x'] = '0' . $pubKey['x'];

        while(strlen($pubKey['y']) < 64)
            $pubKey['y'] = '0' . $pubKey['y'];

        $derPubKey = $this->getDerPubKeyWithPubKeyPoints($pubKey, $isCompressed);


        if($this->checkSignaturePoints($derPubKey, $R, $S, $hash))
            return $derPubKey;
        else
            return false;

    }

    /***
     * Check signature with public key R & S values of the signature and the message hash.
     *
     * @param $pubKey
     * @param $R
     * @param $S
     * @param $hash
     * @return bool
     */
    public function checkSignaturePoints($pubKey, $R, $S, $hash)
    {
        $G = $this->G;

        $pubKeyPts = $this->getPubKeyPointsWithDerPubKey($pubKey);

        // S^-1* hash * G + S^-1 * R * Qa

        // S^-1* hash
        $exp1 =  gmp_strval(
                            gmp_mul(
                                    gmp_invert(
                                               gmp_init($S, 16),
                                               $this->n
                                    ),
                                    gmp_init($hash, 16)
                            ),
                            16
                 );

        // S^-1* hash * G
        $exp1Pt = $this->mulPoint($exp1, $G);


        // S^-1 * R
        $exp2 =  gmp_strval(
                            gmp_mul(
                                    gmp_invert(
                                               gmp_init($S, 16),
                                                $this->n
                                    ),
                                    gmp_init($R, 16)
                            ),
                            16
                 );
        // S^-1 * R * Qa

        $pubKeyPts['x'] = gmp_init($pubKeyPts['x'], 16);
        $pubKeyPts['y'] = gmp_init($pubKeyPts['y'], 16);

        $exp2Pt = $this->mulPoint($exp2,$pubKeyPts);

        $resultingPt = $this->addPoints($exp1Pt, $exp2Pt);

        $xRes = gmp_strval($resultingPt['x'], 16);

        while(strlen($xRes) < 64)
            $xRes = '0' . $xRes;

        if($xRes == $R)
            return true;
        else
            return false;
    }

    /***
     * checkSignaturePoints wrapper for DER signatures
     *
     * @param $pubKey
     * @param $signature
     * @param $hash
     * @return bool
     */
    public function checkDerSignature($pubKey, $signature, $hash)
    {
        $signature = hex2bin($signature);
        if('30' != bin2hex(substr($signature, 0, 1)))
            return false;

        $RLength = hexdec(bin2hex(substr($signature, 3, 1)));
        $R = bin2hex(substr($signature, 4, $RLength));

        $SLength = hexdec(bin2hex(substr($signature, $RLength + 5, 1)));
        $S = bin2hex(substr($signature, $RLength + 6, $SLength));

        //echo "\n\nsignature:\n";
        //print_r(bin2hex($signature));

        //echo "\n\nR:\n";
        //print_r($R);
        //echo "\n\nS:\n";
        //print_r($S);

        return $this->checkSignaturePoints($pubKey, $R, $S, $hash);
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
        preg_match_all("#-----BEGIN BITCOIN SIGNED MESSAGE-----\n(.{0,})\n-----BEGIN SIGNATURE-----\n#USi", $rawMessage, $out);
        $message = $out[1][0];

        preg_match_all("#\n-----BEGIN SIGNATURE-----\n(.{0,})\n(.{0,})\n-----END BITCOIN SIGNED MESSAGE-----#USi", $rawMessage, $out);
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
        $hash = $this->hash256("\x18Bitcoin Signed Message:\n" . $this->numToVarIntString(strlen($message)) . $message);


        //recover flag
        $signature = base64_decode($encodedSignature);

        $flag = hexdec(bin2hex(substr($signature, 0, 1)));

        $R = bin2hex(substr($signature, 1, 64));
        $S = bin2hex(substr($signature, 65, 64));



        $derPubKey = $this->getPubKeyWithRS($flag, $R, $S, $hash);


        $recoveredAddress = $this->getAddress($derPubKey);


        if($address == $recoveredAddress)
            return true;
        else
            return false;
    }
}

?>