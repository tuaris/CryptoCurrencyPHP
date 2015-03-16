<?php
/* 
 * Private Key
 * For Bitcoin/Zetacoin compatable Crypto Currency utilizing the secp256k1 curve
 * @author Daniel Morante
 * Some parts may contain work based on Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt
*/

 class PrivateKey{
 
    public $k;

    public function __construct($private_key = null){
		if (empty($private_key)){
			$this->generateRandomPrivateKey();
		}
		else{
			$this->setPrivateKey($private_key);
		}
    }

    /***
     * Generate a new random private key.
     * The extra parameter can be some random data typed down by the user or mouse movements to add randomness.
     *
     * @param string $extra
     * @throws \Exception
     */
    public function generateRandomPrivateKey($extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d')
    {
		$secp256k1 = new SECp256k1();
		$n = $secp256k1->n;

        //private key has to be passed as an hexadecimal number
        do { //generate a new random private key until to find one that is valid
            $bytes      = openssl_random_pseudo_bytes(256, $cStrong);
            $hex        = bin2hex($bytes);
            $random     = $hex . microtime(true).rand(100000000000, 1000000000000) . $extra;
            $this->k    = hash('sha256', $random);

            if(!$cStrong)
            {
                throw new \Exception('Your system is not able to generate strong enough random numbers');
            }

        } while(gmp_cmp(gmp_init($this->k, 16), gmp_sub($n, gmp_init(1, 10))) == 1);
    }

    /***
     * return the private key.
     *
     * @return String Hex
     */
    public function getPrivateKey()
    {
        return $this->k;
    }

    /***
     * set a private key.
     *
     * @param String Hex $k
     * @throws \Exception
     */
    public function setPrivateKey($k)
    {
		$secp256k1 = new SECp256k1();
		$n = $secp256k1->n;
        
        //private key has to be passed as an hexadecimal number
        if(gmp_cmp(gmp_init($k, 16), gmp_sub($n, gmp_init(1, 10))) == 1)
        {
            throw new \Exception('Private Key is not in the 1,n-1 range');
        }
        $this->k = $k;
    }

    /***
     * returns the X and Y point coordinates of the public key.
     *
     * @return Array Point
     * @throws \Exception
     */
    public function getPubKeyPoints()
    {
        $secp256k1 = new SECp256k1();
		$G = $secp256k1->G;
		$a = $secp256k1->a;
		$b = $secp256k1->b;
		$p = $secp256k1->p;
        $k = $this->k;

        if(!isset($this->k))
        {
            throw new \Exception('No Private Key was defined');
        }

        $pubKey 	    = PointMathGMP::mulPoint($k,
                                          array('x' => $G['x'], 'y' => $G['y']),
										  $a,
										  $b,
										  $p
                                 );

        $pubKey['x']	= gmp_strval($pubKey['x'], 16);
        $pubKey['y']	= gmp_strval($pubKey['y'], 16);

        while(strlen($pubKey['x']) < 64)
        {
            $pubKey['x'] = '0' . $pubKey['x'];
        }

        while(strlen($pubKey['y']) < 64)
        {
            $pubKey['y'] = '0' . $pubKey['y'];
        }

        return $pubKey;
    }

 }
?>