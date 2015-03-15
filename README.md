# Crypto Currency for PHP

A collection of common utilities and libraries in PHP for use with Bitcoin and Zetacoin compatable crypto currencies ustilizing the secp256k ECDSA curve.

I doubt most of this works at the moment since I'm still pulling things together.  The current (planned) features include:

- Message Signing and verification
- Address Generation and Validation
- Address compression, de-compression, enconding, and de-enconding.
 
Currently, the following items are working

- Base58.class.php
- PointMathGMP.class.php
- AddressCodec.class.php

The current implementation requires the php5-gmp extension.

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

Based on work by Jan Moritz Lindemann, Matyas Danter, and Joey Hewitt
