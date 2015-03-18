<?php

/*
 * Crypto Currency Address Codec Library
 * For use with Bitcoin and Zetacoin compatable crypto currency using the secp256k1 ECC curve
 *
 * @author Daniel Morante
 * Some parts may contain work based on Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt
*/


class AddressCodec{
    /***
     * returns the Uncompressed DER encoded public key.
     *
     * @return String Hex
     */
    public static function Hex(Array $point)
    {
        $derPubKey = '04' . $point['x'] . $point['y'];
        return $derPubKey;
    }

    /***
     * returns the public key coordinates as an array.
	 * Input can be compressed or uncompressed DER Encoded Pubkey
     *
     * @return array
     */
	public static function Point($derPubKey){
		if(substr($derPubKey, 0, 2) == '04' && strlen($derPubKey) == 130){
            //uncompressed der encoded public key
            $x = substr($derPubKey, 2, 64);
            $y = substr($derPubKey, 66, 64);
            return array('x' => $x, 'y' => $y);
        }
		// Oops This is actually a compressed DER Public Key, send it to the correct function
		elseif((substr($derPubKey, 0, 2) == '02' || substr($derPubKey, 0, 2) == '03') && strlen($derPubKey) == 66){
			return self::Decompress($derPubKey);
		}
        else
        {
            throw new \Exception('Invalid derPubKey format : ' . $compressedDerPubKey);
        }
	}
	
	
    /***
     * returns the public key coordinates as an array.
	 * Input can be compressed or uncompressed DER Encoded Pubkey
     *
     * @param $derPubKey
     * @return array
     * @throws \Exception
     */
    public static function Decompress($compressedDerPubKey) {
        if((substr($compressedDerPubKey, 0, 2) == '02' || substr($compressedDerPubKey, 0, 2) == '03') && strlen($compressedDerPubKey) == 66){
            //compressed der encoded public key
            $x = substr($compressedDerPubKey, 2, 64);
			// secp256k1
			$secp256k1 = new SECp256k1();
			$a = $secp256k1->a;
			$b = $secp256k1->b;
			$p = $secp256k1->p;
			// This is where the magic happens
            $y = PointMathGMP::calculateYWithX($x, $a, $b, $p, substr($compressedDerPubKey, 0, 2));
            return array('x' => $x, 'y' => $y);
        }
		// OOps.. This is actually a non-compressed DER Public Key, send it to the correct function
		elseif(substr($compressedDerPubKey, 0, 2) == '04' && strlen($compressedDerPubKey) == 130){
			return self::Point($compressedDerPubKey);
		}
        else{
            throw new \Exception('Invalid compressedDerPubKey format : ' . $compressedDerPubKey);
        }
    }
    /***
     * returns the compressed DER encoded public key.
     *
     * @return String Hex
     */
    public static function Compress($pubKey){
        if(gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), gmp_init(2, 10))) == 0)
            $compressedDerPubKey  	= '02' . $pubKey['x'];	//if $pubKey['y'] is even
        else
            $compressedDerPubKey  	= '03' . $pubKey['x'];	//if $pubKey['y'] is odd

        return $compressedDerPubKey;
    }

    /***
     * returns the HASH160 version of the Publick Key 
     * .
     *
     * @param string $derPubKey
     * @throws \Exception
     * @return String Hash160
     */
	public static function Hash($derPubKey){
		$sha256		    = hash('sha256', hex2bin($derPubKey));
		$ripem160 	    = hash('ripemd160', hex2bin($sha256));
		return $ripem160;
	}

    /***
     * returns the Bitcoin address version of the Publick Key 
     * .
     *
     * @param string $hex
     * @throws \Exception
     * @return String Base58
     */
    public static function Encode($hex, $prefix = "00") {
		// The magical prefix
		$hex_with_prefix	= $prefix . $hex;
        
		//checksum
        $sha256			= hash('sha256', hex2bin($hex_with_prefix));
        $checksum		= hash('sha256', hex2bin($sha256));

		// Encode
        $address		= $hex_with_prefix . substr($checksum, 0, 8);
        $address		= Base58::Encode($address);

		return $address;
    }

	public static function Decode($address) {
		$hex_with_prefix_and_check = Base58::Decode($address);
		$prefix = substr($hex_with_prefix_and_check, 0, 2);
		$checksum = substr($hex_with_prefix_and_check, -8);
		$hex = substr($hex_with_prefix_and_check, 2, -8);
		return $hex;
	}

	/***
	 * returns the private key under the Wallet Import Format
	 *
	 * @return String Base58
	 * @throws \Exception
	 */
	public static function WIF($private_key, $prefix = '80', $compressed = true){
		if ($compressed) {$private_key = $private_key . '01';}
		return strrev(self::Encode($private_key, $prefix));
	}

	public static function DeWIF($wif, $compressed = true){
		$base58 = strrev($wif);
		$hex = self::Decode($base58);
		if ($compressed) {$hex = substr($hex, 0, -2);}
		return $hex;
	}
}
?>
