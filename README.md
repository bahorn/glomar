# Glomar

Implementation of a deniable storage system.
You add files, and it is not possible to determine how many files are in the
volume after it is packed.
(Beyond an upper bound of how many blocks there are)

We can neither confirm or deny the existance of this file :)

Usual disclaimer that is hacky software I wrote because I found it fun, not
actually for any real secure use.
* No real error handling
* its slow for large volumes
* it literally uses pickle
* There are a bunch of cases that this breaks in, that require knowledge of
  internals to avoid.
* You can't use the same key twice in a volume, this breaks detection right
  now.

You can perform differential attacks if you don't completely regen the volume
from scratch.
Which lets you determine which blocks were modified.

## Usage

This is meant to be used as a library, but there is a CLI for testing.

Create a volume:
```
python3 glomar create --n_blocks 1000 volume
```


Add a file to the volume with the key `magic`:
```
python3 glomar add volume magic /etc/passwd
```


Pack a volume and finalize it:
```
python3 glomar pack volume finished
```


Read a file back out:
```
python3 glomar get finished magic
```


## Cryptography

ChaCha20 to encrypt data.
Each block has a sha256 hmac, which is how valid blocks are identified.
