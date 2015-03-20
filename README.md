# Crypto Currency for PHP

A collection of common utilities and libraries in PHP for use with Bitcoin and Zetacoin compatable crypto currencies ustilizing the secp256k1 ECDSA curve.  Full documentation and extended examples are avialable at: http://www.unibia.com/unibianet/developer/crypto-currency-php-libraries-pure-php-zetacoin-and-bitcoin-compatable-crypto-currencies

The code may be messy and all over the place, but I'm still pulling things together as I merge this code base with items from the PHPECC codebase.  The current features include:

- Private Key Generation and Loading
- Public Address Print Out
- Message Signing and Verification
- Address Generation and Validation
- Address compression, de-compression, encoding, and decoding.
- Supports Arbitrary Address Prefixes
 
Currently, the following items are working

- Base58.class.php
- SECp256k1.class.php
- PointMathGMP.class.php
- AddressValidation.class.php
- AddressCodec.class.php
- PrivateKey.class.php
- Signature.class.php
- Wallet.class.php

Planned features include:

- Transaction Generation
- Transaction Signing

No ETA.

## Requirements 

The current implementation requires the php5-gmp extension.  Future version will automaticly detect and switch between GMP and BCMATH

## Usage

### AddressCodec

The AddressCodec class provides a simple interface for common Zetacoin/Bitcoin (and compatable) address functions.  Load the following classes in your PHP code:
```PHP
include 'Base58.class.php';
include 'PointMathGMP.class.php';
include 'AddressCodec.class.php';
```

The most basic example, get the X and Y coordnates of a DER Encoded public key (old format)
```PHP
$derPublicKey = '04a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235';

$point = AddressCodec::Point($derPublicKey);

echo $point['x'];
echo $point['y'];
```

That will return an array with both X and Y:
```
X = a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd
Y = 5b8dec5235a0fa8722476c7709c02559e3aa73aa03918ba2d492eea75abea235
```

The more usefull method is with the new compressed public keys used by modern crypto currencies:
```PHP
$compressedPublicKey = '03a34b99f22c790c4e36b2b3c2c35a36db06226e41c692fc82b8b56ac1c540c5bd';

$point = AddressCodec::Decompress($compressedPublicKey);

echo $point['x'];
echo $point['y'];
```

Works the other way around too:
```PHP
$compressedPublicKey = AddressCodec::Compress($point);
$derPublicKey = AddressCodec::Hex($point);
```

On to the more usefull items, Encode a public key into a Crypto Currency address.  First Hash your public key then Encode it.
```PHP
$hash = AddressCodec::Hash($compressedPublicKey);
$address = AddressCodec::Encode($hash);

echo $address;
```

Gives you:
```
Address = 1F3sAm6ZtwLAUnj7d38pGFxtP3RVEvtsbV
```

Specify your own prefix (in HEX):
```PHP
$address = AddressCodec::Encode($hash, "50");
```

Gives you:
```
Address = ZS67wSwchNQFuTt3abnK4HjpjQ2x79YZed
```

### Wallet

The Wallet class provides a simple interface to common Zetacoin/Bitcoin (and compatable) functions.  At the moment, the wallet can load a private key, display it's associated receive address, and of course, message signing/verification!

To use this, load the following classes in your PHP code:
```PHP
include 'Base58.class.php';
include 'SECp256k1.class.php';
include 'PointMathGMP.class.php';
include 'AddressCodec.class.php';
include 'PrivateKey.class.php';
include 'Wallet.class.php';
include 'Signature.class.php';
```

First you must generate or specify a PrivateKey:
```PHP
$private = new PrivateKey('1234567890abcdefNOTAREALKEY23456789012345678789');
# Or
$private = new PrivateKey();
```

Load this PrivateKey into the Wallet. Optionally set the network prefix (aka address version/prefix) as a HEX, and network name.
```PHP
$wallet = new Wallet($private);
# Setting "Z" for "Zetacoin" Address version is 80 in decimal. '50' in HEX.
$wallet->setNetworkPrefix("50");
$wallet->setNetworkName("Zetacoin");
```

Print out your recieve address:
```PHP
echo $wallet->getAddress();
```

Sign a message in pure PHP!!!
```PHP
echo $message =  $wallet->signMessage("Test 1234");
```

Puts out something like:
```
-----BEGIN ZETACOIN SIGNED MESSAGE-----
Test 1234
-----BEGIN SIGNATURE-----
ZJFVhALJwWV1uz8m1YoXXyvNqFMu4h7A94
H7wVT/QJEd3xIonGorLsDxXHg8DE5byo9fcD5h/LHH02KX7nFKjyvH7AE7PjioCQid4qKOjuMh430G37gKIupDc=
-----END ZETACOIN SIGNED MESSAGE-----
```

Verify a signed message using the Satoshi client's standard message signature format. 
A PrivateKey is not required when you only need to verify signed messsages.
```PHP
$message = PHP_EOL;
$message .= "-----BEGIN ZETACOIN SIGNED MESSAGE-----" . PHP_EOL;
$message .= "Test 1234" . PHP_EOL;
$message .= "-----BEGIN SIGNATURE-----" . PHP_EOL;
$message .= "ZJFVhALJwWV1uz8m1YoXXyvNqFMu4h7A94" . PHP_EOL;
$message .= "H7wVT/QJEd3xIonGorLsDxXHg8DE5byo9fcD5h/LHH02KX7nFKjyvH7AE7PjioCQid4qKOjuMh430G37gKIupDc=" . PHP_EOL;
$message .= "-----END ZETACOIN SIGNED MESSAGE-----";

$wallet = new Wallet();
$wallet->setNetworkPrefix("50");
$wallet->setNetworkName("Zetacoin");

echo $wallet->checkSignatureForRawMessage($message) ? 'Verifies' : 'Fails';
```
_Note that the line endings are important since the parser is quite picky at the moment  This will be fixed in a later release._

**Yes, it's pure PHP!**

If you don't want to bother with line endings, you can feed the components in manually:
```PHP
$message = "Test 1234";
$address = "ZJFVhALJwWV1uz8m1YoXXyvNqFMu4h7A94";
$signature = "H7wVT/QJEd3xIonGorLsDxXHg8DE5byo9fcD5h/LHH02KX7nFKjyvH7AE7PjioCQid4qKOjuMh430G37gKIupDc=";

$wallet = new Wallet();
$wallet->setNetworkPrefix("50");
$wallet->setNetworkName("Zetacoin");

echo $wallet->checkSignatureForMessage($address, $signature, $message) ? 'Verifies' : 'Fails';
```

If you find this usefull, please send me some

Bitcoin: 1B6eyXVRPxdEitW5vWrUnzzXUy6o38P9wN

Zetacoin: ZK6kdE5H5q7H6QRNRAuqLF6RrVD4cFbiNX

*The items in the repository may contain some derivative work based on Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt*
