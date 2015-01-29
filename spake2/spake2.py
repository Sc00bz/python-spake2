
import os, binascii, re
from hashlib import sha256

# TODO: include idP and idQ as strings
# TODO: include X and Y in the hash
# TODO: switch to ECC


class PAKEError(Exception):
    pass
class BadUVString(Exception):
    """The U and V strings must be simple ASCII for serializability"""
def orderlen(x): return 1
from .util import string_to_number

# inverse_mod is copied from my python-ecdsa package, originally written by
# Peter Pearson and placed in the public domain.
def inverse_mod( a, m ):
  """Inverse of a mod m."""

  if a < 0 or m <= a: a = a % m

  # From Ferguson and Schneier, roughly:

  c, d = a, m
  uc, vc, ud, vd = 1, 0, 0, 1
  while c != 0:
    q, c, d = divmod( d, c ) + ( c, )
    uc, vc, ud, vd = ud - q*uc, vd - q*vc, uc, vc

  # At this point, d is the GCD, and ud*a+vd*m = d.
  # If d == 1, this means that ud is a inverse.

  assert d == 1
  if ud > 0: return ud
  else: return ud + m


class SPAKE2:
    """This class manages one half of a SPAKE2 key negotiation.

    The protocol has four public system parameters: a group, a generator, and
    two group elements (one each for sides P and Q). The participants must
    agree ahead of time which role each will play (either P or Q).

    Create an instance with SPAKE2(password=pw, side='P') (or side='Q'), where
    'password' is either a number (0 < number < params.q-1) or a bytestring.
    You can also pass an optional params= value (one of [params_80,
    params_112, params_128], for increasing levels of security and CPU
    usage). Any two PAKE communicating instances must use different
    side= values.

    Once constructed, you will need to call one() and two() in order, passing
    the output of one() over the wire, where it forms the input to two():

        my_msg1 = p.one()
        send(my_msg1)
        their_msg1 = receive()
        key = p.two(their_msg1)

    The secret 'key' that comes out will be a bytestring (the output of a
    hash function). If both sides used the same password, both sides will
    wind up with the same key, otherwise they will have different keys. You
    will probably want to confirm this equivalence before relying upon it
    (but don't reveal the key to the other side in doing so, in case you
    aren't talking to the right party and your keys are really different).
    Note that this introduces an additional asymmetry to the protocol (one
    side learns of the mismatch before the other). For example:

        A: hhkey = sha256(sha256(Akey).digest()).digest()
        A: send(hhkey)
          B: hhkey = receive()
          B: assert sha256(sha256(Bkey).digest()).digest() == hhkey
          B: hkey = sha256(Bkey).digest()
          B: send(hkey)
        A: hkey = receive()
        A: assert sha256(Akey).digest() == hkey

    If you can't keep the SPAKE2 instance alive for the whole negotiation, you
    can persist the important data from an instance with data=p.to_json(),
    and then reconstruct the instance with p=SPAKE2.from_json(data). The
    instance data is sensitive: protect it better than you would the original
    password. An attacker who learns the instance state from both sides will
    be able to reconstruct the shared key. These functions return a
    dictionary: you are responsible for invoking e.g. simplejson.dumps() to
    serialize it into a string that can be written to disk. For params_80,
    the serialized JSON is typically about 1236 bytes after construction and
    1528 bytes after one().

     p = SPAKE2(password)
     send(p.one())
     open('save.json','w').write(simplejson.dumps(p.to_json()))
     ...
     p = SPAKE2.from_json(simplejson.loads(open('save.json').read()))
     key = p.two(receive())

    The message returned by one() is a small dictionary, safe to serialize as
    a JSON object, and will survive being deserialized in a javascript
    environment (i.e. the large numbers are encoded as hex strings, since JS
    does not have bigints). If you wish for smaller messages, the SPAKE2
    instance has pack_msg() and unpack_msg() methods to encode/decode these
    strings into smaller bytestrings. The encoding scheme is slightly
    different for each params= value. For params_80, a JSON encoding of
    one() is 265 bytes, and the pack_msg() encoding is 129 bytes.

      send(p.pack_msg(p.one()))
      key = p.two(p.unpack_msg(receive()))

    """

    def __init__(self, password, side, params=params_80, entropy=None):
        if entropy is None:
            entropy = os.urandom
        self.entropy = entropy
        if side not in ["P","Q"]:
            raise PAKEError("side= must be either P or Q")
        self.side = side
        self.params = params
        q = params.q
        if isinstance(password, int):
            assert password > 0
            assert password < q-1
            self.s = password
        else:
            assert isinstance(password, bytes)
            # we must convert the password (a variable-length string) into a
            # number from 1 to q-1 (inclusive).
            self.s = 1 + (string_to_number(sha256(password).digest()) % (q-1))

    def one(self):
        g = self.params.g; p = self.params.p; q = self.params.q
        # self.ab is known as alpha on side P, and beta on side Q
        self.ab = randrange(q, self.entropy) # [0,q)
        if self.side == "P":
            upw = pow(self.params.u, self.s, p)
            self.xy = XY = (pow(g, self.ab, p) * upw) % p
            return {"X": "%x"%XY}
        else:
            vpw = pow(self.params.v, self.s, p)
            self.xy = XY = (pow(g, self.ab, p) * vpw) % p
            return {"Y": "%x"%XY}
        # XY is known as X on side P, and Y on side Q
        # serialize it with a simple jsonable dict for now

    def two(self, msg):
        p = self.params.p
        if self.side == "P":
            X = self.xy
            Y = int(msg["Y"], 16)
            vpw_inv = pow(self.params.inv_v, self.s, p)  # 1/V*pw
            Z = pow((Y * vpw_inv) % p, self.ab, p)
        else:
            X = int(msg["X"], 16)
            Y = self.xy
            upw_inv = pow(self.params.inv_u, self.s, p)  # 1/U*pw
            Z = pow((X * upw_inv) % p, self.ab, p)


        # now compute H(s, (idP,idQ), X, Y, Z)
        t = "%x:%x:%x:%x" % (self.s, X, Y, Z)
        # we don't use the idP/idQ salts
        key = sha256(t).digest()
        return key

    def pack_msg(self, data):
        orderlen = self.params.orderlen
        def n2s(hexint):
            return number_to_string(int(hexint,16), orderlen)
        if "X" in data:
            side = "\x00"
            XY = data["X"]
        else:
            assert "Y" in data
            side = "\x01"
            XY = data["Y"]
        packed = side + n2s(XY)
        return packed

    def unpack_msg(self, packed):
        if packed[0] == "\x00":
            return {"X": binascii.hexlify(packed[1:])}
        else:
            return {"Y": binascii.hexlify(packed[1:])}

    def getattr_hex(self, name):
        if hasattr(self, name):
            return "%x" % getattr(self, name)
        return None

    def to_json(self):
        return {"side": self.side,
                "params.p": "%x" % self.params.p,
                "params.g": "%x" % self.params.g,
                "params.q": "%x" % self.params.q,

                "params.u_str": self.params.u_str,
                "params.v_str": self.params.v_str,

                "s": self.s,
                "ab": self.getattr_hex("ab"),
                "xy": self.getattr_hex("xy"),
                }

    @classmethod
    def from_json(klass, data, entropy=None):
        p = Params(p=int(data["params.p"], 16),
                   q=int(data["params.q"], 16),
                   g=int(data["params.g"], 16),
                   u=data["params.u_str"],
                   v=data["params.v_str"])
        self = klass(data["s"], data["side"], params=p, entropy=entropy)
        for name in ["ab", "xy"]:
            if data[name]:
                setattr(self, name, int(data[name], 16))
        return self

class SPAKE2_P(SPAKE2):
    def __init__(self, password, params=params_80, entropy=None):
        SPAKE2.__init__(self, password, "P", params, entropy)

class SPAKE2_Q(SPAKE2):
    def __init__(self, password, params=params_80, entropy=None):
        SPAKE2.__init__(self, password, "Q", params, entropy)


# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version
