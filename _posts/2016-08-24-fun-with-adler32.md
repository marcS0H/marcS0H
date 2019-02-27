---
layout: post
title:  "Fun with Adler-32"
tags: [ctf, experiment, adler32, cryptography]
---
As is often the case when reading code written by someone else, I stumbled upon some curious DIY password generation snippet that used the [Adler-32](https://en.wikipedia.org/wiki/Adler-32) checksum function to _extend_ users passwords in a very weird, counter-intuitive and _not-exactly-safer_ manner. Having never really toyed with this algorithm in a context where it is assumed to be a _cryptographically secure hashing function_ (protip: [it wasn't designed for this purpose](https://en.wikipedia.org/wiki/Adler-32)), I decided to make a simple use-case, in form of a simple CTF challenge, to get a better idea of the consequences of using it as such.


## The Challenge
The challenge was simple: it was a file repository page, linking to some publicly shared files. To access a file, the page would take two parameters: "_file"_ and "_sig"_. Simply put, "_file_" would contain the file to grab and "_sig_" a hash signature to prove this is a safe file to show publicly (we don't want a user to grab /etc/passwd, for example. At least not _that_ easily)

The signature would be a combination of a secret prefix (in this case, a _newbie's_ way to prevent an attacker from forging his own file signatures) and the file path itself.

When finished, I came up with the following challenge code:
```php
<?php
 
  define('PREFIX','prefix_unknown_to_the_user');
  function hashit($input) {
    return hash('adler32', $input);
  }

  if( !empty($_GET['file']) &amp;&amp; !empty($_GET['sig']) ) {
    if( $_GET['sig'] === hashit(PREFIX . $_GET['file']) ) {
      echo file_get_contents($_GET['file']);
      die();
    }
    die('INVALID SIGNATURE!');
  }
?>
<html>
  <head>
    <title>Marc's damn (in)secure file repo</title>
  </head>
  <body>
    <h1>My files:</h1>
    <ul>
    <?php
      $files = scandir('files/');
      foreach( $files as $file ) {
        if( in_array($file, array('..', '.')) ) continue;
    ?>
      <li><a href="/?file=<?='./files/'.$file?>&amp;sig=<?=hashit(PREFIX.'./files/'.$file)?>"><?='./files/'.$file?></a></li>
      <br />
    <?php
      }
    ?>
    </ul>
  </body>
</html>
```
With the test environment ready, all that remained was to actually test Adler-32 itself.
## Playing with Adler-32
A quick research on Wikipedia is all it took to get a very good idea of [how the whole thing worked](https://en.wikipedia.org/wiki/Adler-32#Example_implementation):
```c
const int MOD_ADLER = 65521;

uint32_t adler32(unsigned char *data, size_t len) /* where data is the location of the data in physical memory and 
                                                      len is the length of the data in bytes */
{
    uint32_t a = 1, b = 0;
    size_t index;
    
    /* Process each byte of the data in order */
    for (index = 0; index < len; ++index)
    {
        a = (a + data[index]) % MOD_ADLER;
        b = (b + a) % MOD_ADLER;
    }
    
    return (b << 16) | a;
}
```

### Adler-32 101
Basically, the _adler32_ function initializes two 16 bits checksums: **a = 1** and **b = 0** (this snippet is from Wikipedia's article on Adler-32, why the author chose *uint32_t* instead of *uint16_t* is totally unknown to me, if anyone can shed some light on this mystery, please do!).

After this step is completed, it will loop through every bytes of the payload and calculate a new **a** and **b** checksum by essentially doing the following:

1. Incrementing **a** with the current byte, and applying a modulo 65521 operation on the result.
2. Incrementing **b** with **a**'s new value and applying the same modulo operation as we did in the first step.

Once it finished looping through all of the payload, the function gives us our final 32 bit checksum by _"concatenating"_ **b's** 16 bits and **a**'s value (which shouldn't exceed 16 bit either, due to the modulo we applied earlier).
###  Adler-32 102
Now that we have a fairly good idea of how Adler-32 works, we can quite easily spot _(at least)_ two interesting properties resulting from the fact it _(mostly)_ only relies on incrementations to do its work:

1. In a scenario where we have a checksum **C** of an unknown string **S** and a string **X** we control and want to concatenate to **S**, we can generate a new checksum **Cʹ** where **Cʹ= Adler32(S + X)** ("+" is a concatenation operator here) by using **C**'s two final 16 bit variables (**b** and **a**) as the algorithm's new starting checksums (instead of **1** and **0**) and running the modified Adler-32 function on **X**.
2. We can also reverse the loop and get to a previous state **Cʹ** if we know the last byte of the payload used to create the original checksum **C**. To do that, we need to subtract our payload's last character from **C**'s 16 bit checksum **a**, then substract **a** from **b** and pack the two together again to form **Cʹ** (remember to apply the modulo operation from the original algorithm each time you subtract a value **a** or **b**, so you don't end up with negative numbers). This process is repeatable for every characters of the payload you know, as long as they're located at the end of your string.

### Moving from   theory  to practice
Code explains more than words, so here's a sample Python script showing the two points explained above.
```python
import sys
import struct

def adler32(data, custom_init=''):
  s = [1,0]
  if custom_init != '': 
    s[0] = struct.unpack('>H', custom_init[2:])[0]
    s[1] = struct.unpack('>H', custom_init[:2])[0]
  for c in data:
    s[0] = (s[0] + ord(c)) % 65521
    s[1] = (s[1] + s[0]) % 65521
  return struct.pack('>I', s[1] << 16 | s[0])

def partial_reverse_adler32(H, last_bytes):
  s = [ 
      struct.unpack('>H', H[2:])[0],
      struct.unpack('>H', H[:2])[0]
  ]
  # Reversing the last bytes
  last_bytes = last_bytes[::-1]
  for c in last_bytes:
    s[1] = (s[1] - s[0]) % 65521
    s[0] = (s[0] - ord(c)) % 65521
  return struct.pack('>I', s[1] << 16 | s[0])

def hash_extension_adler32(H, new_bytes):
  return adler32(new_bytes, H)
if sys.argv[1] == 'hash':
  '''
    Simply hashes a payload with Adler32
    USAGE: python adler32.py hash <payload>
  '''
  print(adler32(sys.argv[2]).encode('hex'))
elif sys.argv[1] == 'reverse':
  '''
    Reverse a hash to an earlier state
    USAGE: python adler32.py reverse <payload> <known_ending_characters>
  '''
  print(partial_reverse_adler32(sys.argv[2].decode('hex'), sys.argv[3]).encode('hex'))
elif sys.argv[1] == 'extend':
  '''
    Extends a hash using an existing state
    USAGE: python adler32.py extend <payload> <known_hash>
  '''
  print(hash_extension_adler32(sys.argv[2].decode('hex'), sys.argv[3]).encode('hex'))
```
Using this tool, we can easily validate what we explained earlier.

```bash
~$ python adler32.py hash test
045d01c1
~$ python adler32.py extend 045d01c1 _succeeded
2c3e05c5
~$ python adler32.py hash test_succeeded
2c3e05c5
~$ python adler32.py reverse 2c3e05c5 _succeeded
045d01c1
```
## Solving   the challenge
That's it, we've done our homeworks, we know how Adler-32 work and we can even play with it! Now, how does this apply to the challenge?

It's easy to see what the challenge actually is about now, the only thing between us and an arbitrary file read vulnerability on the server is an Adler-32 checksum of a secret prefix, unknown to the visitor, and the path of the file we want to see. The solution is then pretty easy to figure, if you read the post. We'll need to:
1. Reverse the checksum's state until we get the secret prefix's checksum
2. Extend this new checksum with the path of the file we want to grab (/etc/passwd for example).
3. _Of course_, push the resulting checksum in the challenge page's **sig** parameter and /etc/passwd in the **file** parameter.

And boom, finished.
## TL;DR
Do not use Adler-32 for anything else than what it was purposely made for. **Ever**.
