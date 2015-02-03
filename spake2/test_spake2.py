
import unittest
#from .spake2 import (SPAKE2, SPAKE2_P, SPAKE2_Q, PAKEError,
#                     params_80, params_112, params_128)
from . import util
from binascii import hexlify
from hashlib import sha256
import json

class Utils(unittest.TestCase):
    def test_binsize(self):
        def sizebb(maxval):
            num_bits = util.size_bits(maxval)
            num_bytes = util.size_bytes(maxval)
            return (num_bytes, num_bits)
        self.failUnlessEqual(sizebb(0x0f), (1, 4))
        self.failUnlessEqual(sizebb(0x1f), (1, 5))
        self.failUnlessEqual(sizebb(0x10), (1, 5))
        self.failUnlessEqual(sizebb(0xff), (1, 8))
        self.failUnlessEqual(sizebb(0x100), (2, 9))
        self.failUnlessEqual(sizebb(0x101), (2, 9))
        self.failUnlessEqual(sizebb(0x1fe), (2, 9))
        self.failUnlessEqual(sizebb(0x1ff), (2, 9))
        self.failUnlessEqual(sizebb(2**255-19), (32, 255))

    def test_number_to_bytes(self):
        n2b = util.number_to_bytes
        self.failUnlessEqual(n2b(0x00, 0xff), b"\x00")
        self.failUnlessEqual(n2b(0x01, 0xff), b"\x01")
        self.failUnlessEqual(n2b(0xff, 0xff), b"\xff")
        self.failUnlessEqual(n2b(0x100, 0xffff), b"\x01\x00")
        self.failUnlessEqual(n2b(0x101, 0xffff), b"\x01\x01")
        self.failUnlessEqual(n2b(0x102, 0xffff), b"\x01\x02")
        self.failUnlessEqual(n2b(0x1fe, 0xffff), b"\x01\xfe")
        self.failUnlessEqual(n2b(0x1ff, 0xffff), b"\x01\xff")
        self.failUnlessEqual(n2b(0x200, 0xffff), b"\x02\x00")
        self.failUnlessEqual(n2b(0xffff, 0xffff), b"\xff\xff")
        self.failUnlessEqual(n2b(0x10000, 0xffffff), b"\x01\x00\x00")
        self.failUnlessEqual(n2b(0x1, 0xffffffff), b"\x00\x00\x00\x01")
        self.failUnlessRaises(ValueError, n2b, 0x10000, 0xff)

    def test_bytes_to_number(self):
        b2n = util.bytes_to_number
        self.failUnlessEqual(b2n(b"\x00"), 0x00)
        self.failUnlessEqual(b2n(b"\x01"), 0x01)
        self.failUnlessEqual(b2n(b"\xff"), 0xff)
        self.failUnlessEqual(b2n(b"\x01\x00"), 0x0100)
        self.failUnlessEqual(b2n(b"\x01\x01"), 0x0101)
        self.failUnlessEqual(b2n(b"\x01\x02"), 0x0102)
        self.failUnlessEqual(b2n(b"\x01\xfe"), 0x01fe)
        self.failUnlessEqual(b2n(b"\x01\xff"), 0x01ff)
        self.failUnlessEqual(b2n(b"\x02\x00"), 0x0200)
        self.failUnlessEqual(b2n(b"\xff\xff"), 0xffff)
        self.failUnlessEqual(b2n(b"\x01\x00\x00"), 0x010000)
        self.failUnlessEqual(b2n(b"\x00\x00\x00\x01"), 0x01)
        self.failUnlessRaises(TypeError, b2n, 42)
        if type("") != type(b""):
            self.failUnlessRaises(TypeError, b2n, "not bytes")

    def test_mask(self):
        gen = util.generate_mask
        self.failUnlessEqual(gen(0x01), (0x01, 1))
        self.failUnlessEqual(gen(0x02), (0x03, 1))
        self.failUnlessEqual(gen(0x03), (0x03, 1))
        self.failUnlessEqual(gen(0x04), (0x07, 1))
        self.failUnlessEqual(gen(0x07), (0x07, 1))
        self.failUnlessEqual(gen(0x08), (0x0f, 1))
        self.failUnlessEqual(gen(0x09), (0x0f, 1))
        self.failUnlessEqual(gen(0x0f), (0x0f, 1))
        self.failUnlessEqual(gen(0x10), (0x1f, 1))
        self.failUnlessEqual(gen(0x7f), (0x7f, 1))
        self.failUnlessEqual(gen(0x80), (0xff, 1))
        self.failUnlessEqual(gen(0xff), (0xff, 1))
        self.failUnlessEqual(gen(0x0100), (0x01, 2))
        self.failUnlessEqual(gen(2**255-19), (0x7f, 32))
        mask = util.mask_list_of_ints
        self.failUnlessEqual(mask(0x03, [0xff, 0x55, 0xaa]), [0x03, 0x55, 0xaa])
        self.failUnlessEqual(mask(0xff, [0xff]), [0xff])
    def test_l2n(self):
        l2n = util.list_of_ints_to_number
        self.failUnlessEqual(l2n([0x00]), 0x00)
        self.failUnlessEqual(l2n([0x01]), 0x01)
        self.failUnlessEqual(l2n([0x7f]), 0x7f)
        self.failUnlessEqual(l2n([0x80]), 0x80)
        self.failUnlessEqual(l2n([0xff]), 0xff)
        self.failUnlessEqual(l2n([0x01, 0x00]), 0x0100)

    def test_unbiased_randrange(self):
        for seed in range(1000):
            self.do_test_unbiased_randrange(0, 254, seed)
            self.do_test_unbiased_randrange(0, 255, seed)
            self.do_test_unbiased_randrange(0, 256, seed)
            self.do_test_unbiased_randrange(0, 257, seed)
            self.do_test_unbiased_randrange(1, 257, seed)

    def do_test_unbiased_randrange(self, start, stop, seed):
        num = util.unbiased_randrange(start, stop, entropy_f=FakeRandom(seed))
        self.failUnless(start <= num < stop, (num, seed))

class FakeRandom:
    def __init__(self, seed):
        self.data = sha256(str(seed).encode("ascii")).digest()
    def __call__(self, num_bytes):
        assert num_bytes < len(self.data)
        ret = self.data[:num_bytes]
        self.data = self.data[num_bytes:]
        return ret


class Basic(unittest.TestCase):
    def test_success(self):
        pw = b"password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(pw)
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

    def test_failure(self):
        pw = b"password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(b"passwerd")
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

class Parameters(unittest.TestCase):
    def do_tests(self, params):
        pw = b"password"
        pA,pB = SPAKE2_P(pw, params=params), SPAKE2_Q(pw, params=params)
        m1A,m1B = pA.one(), pB.one()
        #print len(json.dumps(m1A))
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

        pA,pB = SPAKE2_P(pw, params=params), SPAKE2_Q(b"passwerd", params=params)
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failIfEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))
        self.failUnlessEqual(len(kB), len(sha256().digest()))

    def test_params(self):
        for params in [params_80, params_112, params_128]:
            self.do_tests(params)

    def test_default_is_80(self):
        pw = b"password"
        pA,pB = SPAKE2_P(pw, params=params_80), SPAKE2_Q(pw)
        m1A,m1B = pA.one(), pB.one()
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))


class PRNG:
    # this returns a callable which, when invoked with an integer N, will
    # return N pseudorandom bytes.
    def __init__(self, seed):
        self.generator = self.block_generator(seed)

    def __call__(self, numbytes):
        return "".join([self.generator.next() for i in range(numbytes)])

    def block_generator(self, seed):
        counter = 0
        while True:
            for byte in sha256("prng-%d-%s" % (counter, seed)).digest():
                yield byte
            counter += 1

class OtherEntropy(unittest.TestCase):
    def test_entropy(self):
        entropy = PRNG("seed")
        pw = b"password"
        pA,pB = SPAKE2_P(pw, entropy=entropy), SPAKE2_Q(pw, entropy=entropy)
        m1A1,m1B1 = pA.one(), pB.one()
        kA1,kB1 = pA.two(m1B1), pB.two(m1A1)
        self.failUnlessEqual(hexlify(kA1), hexlify(kB1))

        # run it again with the same entropy stream: all messages should be
        # identical
        entropy = PRNG("seed")
        pA,pB = SPAKE2_P(pw, entropy=entropy), SPAKE2_Q(pw, entropy=entropy)
        m1A2,m1B2 = pA.one(), pB.one()
        kA2,kB2 = pA.two(m1B2), pB.two(m1A2)
        self.failUnlessEqual(hexlify(kA2), hexlify(kB2))

        self.failUnlessEqual(m1A1, m1A2)
        self.failUnlessEqual(m1B1, m1B2)
        self.failUnlessEqual(kA1, kA2)
        self.failUnlessEqual(kB1, kB2)

class Serialize(unittest.TestCase):
    def replace(self, orig):
        data = json.dumps(orig.to_json())
        #print len(data)
        return SPAKE2.from_json(json.loads(data))

    def test_serialize(self):
        pw = b"password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(pw)
        pA = self.replace(pA)
        m1A,m1B = pA.one(), pB.one()
        pA = self.replace(pA)
        kA,kB = pA.two(m1B), pB.two(m1A)
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

class Packed(unittest.TestCase):
    def test_pack(self):
        pw = b"password"
        pA,pB = SPAKE2_P(pw), SPAKE2_Q(pw)
        m1A,m1B = pA.one(), pB.one()
        m1Ap = pA.pack_msg(m1A)
        #print "m1:", len(json.dumps(m1A)), len(m1Ap)
        kA,kB = pA.two(m1B), pB.two(pB.unpack_msg(m1Ap))
        self.failUnlessEqual(hexlify(kA), hexlify(kB))
        self.failUnlessEqual(len(kA), len(sha256().digest()))

class Errors(unittest.TestCase):
    def test_bad_side(self):
        self.failUnlessRaises(PAKEError,
                              SPAKE2, b"password", "R", params_80)

del Basic, Parameters, PRNG, OtherEntropy, Serialize, Packed, Errors

if __name__ == '__main__':
    unittest.main()

