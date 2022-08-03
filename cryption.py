#!/usr/bin/env python3
#
# This file is an example of one possible way to encrypt data such that the encrypted output is in a form that is easily
# "readable" (or at least pronouncible) by humans.  It takes its input (which this program assumes to be text, but
# making it work with binary data would not be difficult), and first compresses it with zlib, then encrypts it using AES
# encryption with the provided passphrase, then takes the result of the encryption and encodes it into words made of
# human-readable syllables.  The result is something that looks like the following:
#
#   $ ./pronenc.py -e dontusethispassword
# [input]
#   Hello world!
# [output]
#   dohepuzu dino rozateji kemeji mu ke tiwazuke nibipe ka kutikopu koso royonufu heru mahafuni bubeta natare heku
#   yadipeto da nedanahi tawowo
#
# This program outputs just one long line of words, but if desired one could break it into multiple lines without any
# problem in decoding, or even make it look more "human-like" by adding punctuation, capitalization, etc.  (The
# decoder implementation will automatically strip out punctuation/capitalization/extra-whitespace/etc, so it won't
# affect decoding.)
#
# This encoding scheme (with the input data represented by two-byte syllables and variable length spacing) results in an
# encoded text output that is approximately 2.8 times as big as the encrypted binary input.  If one is encrypting text,
# however, then the initial zlib pass can reduce that size significantly for large inputs (usually by half or more),
# resulting in an output size that's usually somewhere between 1.0 and 1.5 times the original document size.
#
# The code here is intended only for demonstration purposes.  It *should* be a reasonably secure implementation of the
# basic principles, but it is definitely not optimal in some ways, and it has not been rigorously examined/tested to
# make sure there aren't vulnerabilities in the encryption implementation, etc.  Use at your own risk!
#
# This program uses the `cryptography` module (https://pypi.org/project/cryptography/) for AES encryption and PBKDF2 key
# derivation.  Aside from that it's all standard Python 3.7 library routines.

import sys
import os
import argparse
import zlib
import io
import re

from cryptography.hazmat.primitives import hashes, ciphers
from cryptography.hazmat.primitives.kdf import pbkdf2
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.backends import default_backend

###############################################################################
# Constants
###############################################################################

# Number of iterations to use in the key derivation function (more iterations is stronger, but takes longer)
PBKDF2_ITER = 100000

# The Initial Vector to use for AES encryption.
# NOTE: In general, DO NOT USE A FIXED IV if you are using a fixed encryption key, as the result can leak data about the
# plaintext in some situations.  We use a fixed IV here because we are already using a salted key derivation function so
# our encryption key will be different every time even when using the same passphrase.  Always carefully evaluate your
# choices of encryption parameters (such as IV) depending on your application, however.
AES_IV = bytes(16)  # all zeros

# The following is the list of syllables we will construct our encoded words from.
#
# These syllables were chosen from the list of Japanese kana syllables, since the Japanese syllabary is handy, fairly
# regular, and conveniently sized (this also has the side-effect that the resulting output could also be transliterated
# directly into hirigana/katakana and easily read/understood by Japanese speakers as well, should that be useful).  Note
# that in Japanese, some of these syllables are pronounced slightly differently than they appear here ("si" = "shi",
# "ti" = "chi", "tu" = "tsu", etc).  These have been adjusted so that we can ensure each syllable is always two
# characters (when represented in ASCII), as it makes decoding simpler.
#
# We are also not using the lone-vowel kana ("a"/"i"/"u"/"e"/"o").  We could use them (and it would be decodable), but
# it would make it more difficult for somebody speaking/hearing certain combinations to reliably communicate them (e.g.
# we could get words like "baaaado" (how many "a"s was that again?) or "oaaiaaoeu" (did you say "oaiiaoouu"?  No, I said
# "oaaiaaoeu"!).  It's just much easier for everyone if we make every syllable always consist of a consonant plus a
# vowel.
#
# We're using 6 bits per syllable (similar to base64 encoding), so we need 65 of these (one each for values 0..63, and
# then one to indicate "EOF padding" (the equivalent of "=" in base64))

SYLLABARY = """
ka ki ku ke ko
sa si su se so
ta ti tu te to
na ni nu ne no
ha hi fu he ho
ma mi mu me mo
ra ri ru re ro
ga gi gu ge go
za ji zu ze zo
da di du de do
ba bi bu be bo
pa pi pu pe po
ya yu yo wa wo
""".split()

# Create a dict to map the reverse direction for decoding, too
SYLLABARY_REV = {SYLLABARY[i]: i for i in range(len(SYLLABARY))}


###############################################################################
# Helper / support classes
###############################################################################

class DecodeError (Exception):
    pass

# Note: The BitReader and BitWriter classes here are really just quick hacks for demonstration purposes, and definitely
# not an optimal implementation.  If you're looking to write a real implementation of this encoding in Python, you may
# want to look into other libraries such as `bitarray` for this sort of bit manipulation instead.

class BitReader (object):
    "Allows taking bytes data and reading through it a few bits at a time"

    def __init__(self, data):
        self.source = io.BytesIO(data)
        self.workspace = 0
        self.bits_avail = 0

    def get_bits(self, count):
        while self.bits_avail < count:
            self.workspace <<= 8
            try:
                self.workspace |= self.source.read(1)[0]
            except IndexError:
                # We hit EOF.  If we have a partial result, just return what we have, padded with zeros
                # If we hit EOF at the start, then raise EOFError
                if not self.bits_avail:
                    raise EOFError('End of data') from None
                self.workspace >>= 8
                result = self.workspace << (count - self.bits_avail)
                self.bits_avail = 0
                return result
            self.bits_avail += 8
        self.bits_avail -= count
        result = self.workspace >> self.bits_avail
        self.workspace &= (1 << self.bits_avail) - 1
        return result


class BitWriter (object):
    "Allows building up a bytes buffer by adding an arbitrary number of bits at a time."

    def __init__(self):
        self.dest = io.BytesIO()
        self.workspace = 0
        self.bits_avail = 0

    def put_bits(self, count, bits):
        self.workspace <<= count
        self.workspace |= bits
        self.bits_avail += count
        while self.bits_avail >= 8:
            value = (self.workspace >> (self.bits_avail - 8)) & 0xff
            self.dest.write(bytes([value]))
            self.bits_avail -= 8
        self.workspace &= (1 << self.bits_avail) - 1

    def result(self):
        if self.workspace != 0:
            # This should never happen.  We have leftover bits that don't fill a whole byte at the end of decoding.
            raise DecodeError("Unexpected trailing bits in decoded data: {}".format(bin(self.workspace)))
        return self.dest.getvalue()


###############################################################################
# Encryption / decryption routines
###############################################################################

def encrypt(passphrase, data):
    salt = os.urandom(16)
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    cipher = ciphers.Cipher(algorithms.AES(key), modes.CBC(AES_IV), backend=default_backend())
    encryptor = cipher.encryptor()
    output = encryptor.update(data)
    # Our input data may not be a multiple of the AES block size, so if necessary pad it out with zeros.
    padding = bytes(-len(data) % 16)
    output += encryptor.update(padding)
    output += encryptor.finalize()
    return salt + output


def decrypt(passphrase, data):
    salt = data[:16]
    input = data[16:]
    kdf = pbkdf2.PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITER,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode('utf-8'))
    cipher = ciphers.Cipher(algorithms.AES(key), modes.CBC(AES_IV), backend=default_backend())
    decryptor = cipher.decryptor()
    output = decryptor.update(input) + decryptor.finalize()
    return output


###############################################################################
# Encoding to/from a pronouncable form
###############################################################################

def encode_word(buffer):
    # The first 2 bits will determine our word length (so our words can be 1-4 syllables in length).  If we hit EOF at
    # the beginning of a word, we just let the EOFError propagate up to the caller and we're done.
    #
    # Note that we should consider the case of hitting EOF halfway through this read (i.e. we read one
    # of the two bits, and then hit EOF): Luckily, we only ever read bits in multiples of 2 or 6, both of which are
    # even, and our input data is in bytes, which are 8-bits (even), so there's no way we could ever hit EOF on an
    # odd-bit boundary, which means we can just not worry about that case here (yay!).
    wordlen = buffer.get_bits(2) + 1

    # Now get `wordlen` syllables, string them together, and return them as a word.
    syllables = []
    for i in range(wordlen):
        # If we can only read some bits, the `get_bits` routine will return the partial result zero-padded.  That's
        # fine for our purposes.  If we're completely at the end, though (no bits left), it will raise EOFError.  In
        # that case, we want to catch the exception and insert padding syllables (value=64) until we reach the end of
        # the word (because otherwise the decoder won't know how long the word was supposed to be, and will get the
        # wrong value out for the "word length" bits).
        try:
            b = buffer.get_bits(6)
        except EOFError:
            b = 64
        syllables.append(SYLLABARY[b])
    return ''.join(syllables)


def encode(data):
    buffer = BitReader(data)
    # Just keep encoding a word at a time until we get to the end, then return the result.
    # Note that a real implementation would probably want to do some sort of streaming process, as the approach here
    # will consume increasingly large amounts of memory the larger the input is.
    words = []
    try:
        while True:
            words.append(encode_word(buffer))
    except EOFError:
        pass
    return ' '.join(words)


def decode_word(buffer, word):
    # The length of the word (in syllables) tells us what the first two decoded bits are
    if len(word) not in [2, 4, 6, 8]:
        raise DecodeError("Invalid word length: {!r} ({})".format(word, len(word)))
    buffer.put_bits(2, (len(word) // 2) - 1)

    # Now for each two characters (syllable), look it up in the reverse dictionary to get the corresponding 6-bit value
    # and add it.
    for i in range(0, len(word), 2):
        syllable = word[i:i+2]
        try:
            bits = SYLLABARY_REV[syllable]
        except KeyError:
            raise DecodeError("Unknown syllable: {!r}".format(syllable)) from None

        # Note: `bits` may be 64 (out of range) if we're decoding padding syllables at the end.  In that case, just
        # don't add anything to our decoded buffer.
        if bits < 64:
            buffer.put_bits(6, bits)


def decode(text):
    buffer = BitWriter()
    # Strip out any non-word-chars and make everything lower case, just in case
    text = re.sub(r'[^A-Za-z\s]', '', text)
    text = text.lower()
    for word in text.split():
        decode_word(buffer, word)
    return buffer.result()


###############################################################################
# Gluing it all together
###############################################################################

def encrypt_and_encode(passphrase, text):
    compressed_data = zlib.compress(text.encode('utf-8'))
    crypted_data = encrypt(passphrase, compressed_data)
    encoded_text = encode(crypted_data)
    return encoded_text


def decode_and_decrypt(passphrase, text):
    crypted_data = decode(text)
    compressed_data = decrypt(passphrase, crypted_data)
    return zlib.decompress(compressed_data).decode('utf-8')


###############################################################################
# Main program start
###############################################################################



# if __name__ == '__main__':
#     parser = argparse.ArgumentParser(description='Pronounceable encryption/decryption')
#     parser.add_argument('--encrypt', '-e', action='store_true', default=True, help='Perform encryption (default)')
#     parser.add_argument('--decrypt', '-d', dest='encrypt', action='store_false', help='Perform decryption')
#     parser.add_argument('passphrase', help='The encryption/decryption key to use')
#
#     args = parser.parse_args()
#     input_text = sys.stdin.read()
#     if args.encrypt:
#         output_text = encrypt_and_encode(args.passphrase, input_text) + '\n'
#     else:
#         output_text = decode_and_decrypt(args.passphrase, input_text)
#     sys.stdout.write(output_text)