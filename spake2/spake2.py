
import os, binascii, re
from hashlib import sha256
from .params import Params1024

# TODO: include idP and idQ as strings
# TODO: include X and Y in the hash
# TODO: switch to ECC


class PAKEError(Exception):
    pass
class BadUVString(Exception):
    """The U and V strings must be simple ASCII for serializability"""

class SPAKE2:
    """This class manages one side of a SPAKE2 key negotiation.

    Two instances of this class, each with the same password, in separate
    processes on either side of a network connection, can cooperatively agree
    upon a strong random session key.

    Both sides must be using the same 'parameters' and the same passwords.
    The sides must play different roles: one side is A, the other side is B.

    Create an instance with SPAKE2(password=pw, side='A') (or side='B'),
    where 'password' is a bytestring. You can also pass an optional params=
    value (one of [params.Params1024, Params2048, Params3072], for increasing
    levels of security and CPU usage). Any two PAKE communicating instances
    must use identical params=, and different side= values.

    Once constructed, you will need to call start() and finish() in order,
    passing the output of start() over the wire, where it forms the input to
    the other instance's finish():

        outbound_message = p.start()
        send(outbound_message) # send to other side, somehow
        inbound_message = receive() # get this from other side, somehow
        key = p.finish(inbound_message)

    The secret 'key' that comes out will be a bytestring of length 256 (the
    output of a SHA256 hash function). If both sides used the same password,
    both sides will wind up with the same key, otherwise they will have
    different keys. You will probably want to confirm this equivalence before
    relying upon it (but don't reveal the key to the other side in doing so,
    in case you aren't talking to the right party and your keys are really
    different). Note that this introduces an additional asymmetry to the
    protocol (one side learns of the mismatch before the other). For example:

        A: hhkey = sha256(sha256(Akey).digest()).digest()
        A: send(hhkey)
          B: hhkey = receive()
          B: assert sha256(sha256(Bkey).digest()).digest() == hhkey
          B: hkey = sha256(Bkey).digest()
          B: send(hkey)
        A: hkey = receive()
        A: assert sha256(Akey).digest() == hkey

    Sometimes, you can't hold the SPAKE2 instance in memory for the whole
    negotiation: perhaps all your program state is stored in a database, and
    nothing lives in RAM for more than a few moments. You can persist the
    data from an instance with `data = p.serialize()`, after the call to
    `start`. Then later, when the inbound message is received, you can
    reconstruct the instance with `p = SPAKE2.from_serialized(data)` and can
    `finish`. The instance data is sensitive: protect it better than you
    would the original password. An attacker who learns the instance state
    from both sides, or an eavesdropper who learns the instance state from
    just one side, will be able to reconstruct the shared key. `data` is a
    printable ASCII string (the JSON-encoding of a small dictionary). For
    params_80, the serialized data is typically about 1528 bytes.

     def first():
       p = SPAKE2(password)
       send(p.start())
       open('saved','w').write(p.serialize())

     def second(inbound_message):
       p = SPAKE2.from_serialized(open('saved').read())
       key = p.finish(inbound_message)
       return key

    The message returned by start() is a bytestring (about 129 bytes long for
    params_80). You may need to base64-encode it before sending it over a
    non-8-bit-clean connection.

    """

    def __init__(self, password, side, idA=b"", idB=b"",
                 params=Params1024, entropy_f=None):
        self.entropy = entropy
        if side not in ["A","B"]:
            raise PAKEError("side= must be either A or B")
        self.side = side
        self.idA = idA
        self.idB = idB
        self.params = params
        group = self.params.group
        assert isinstance(password, bytes)
        self.password = password
        # These names come from the Abdalla/Pointcheval paper.
        #  variable .. known as .. on A's side, and .. on B's side:
        #        self.xy        x                   y
        #        MN             M                   N
        #        NM             N                   M
        self.xy_exp, self.xy_elem = group.random_element(self.entropy)
        self.pw_scalar = group.password_to_scalar(password)
        if side == "A":
            self.MN, self.NM = (params.M, params.N)
        else:
            self.MN, self.NM = (params.N, params.M)
        message_elem = self.xy_elem + (self.MN * self.pw_scalar)
        self.message = group.element_to_bytes(message_elem)

    def start(self):
        # guard against both sides using the same side=
        # add a side byte to the message
        return self.message

    def finish(self, inbound_message):
        if self.side == "A":
            X_msg = self.message
            Y_msg = inbound_message
        else:
            X_msg = inbound_message
            Y_msg = self.message
        inbound_elem = self.params.group.element_from_bytes(inbound_message)
        K_elem = (inbound_elem + (self.NM * -self.pw_scalar)) * self.xy_exp
        K_bytes = self.params.group.element_to_bytes(K_elem)
        key = sha256.digest(b":".join([self.idA, self.idB,
                                       X_msg, Y_msg, K_bytes,
                                       self.pw]))
        return key


    @classmethod
    def from_serialized(klass, data):
        ## p = Params(p=int(data["params.p"], 16),
        ##            q=int(data["params.q"], 16),
        ##            g=int(data["params.g"], 16),
        ##            u=data["params.u_str"],
        ##            v=data["params.v_str"])
        XXX
        self = klass(data["pw"], data["side"], params=p, entropy=entropy)
        for name in ["ab", "xy"]:
            if data[name]:
                setattr(self, name, int(data[name], 16))
        return self

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

class SPAKE2_P(SPAKE2):
    def __init__(self, password, params=params_80, entropy=None):
        SPAKE2.__init__(self, password, "P", params, entropy)

class SPAKE2_Q(SPAKE2):
    def __init__(self, password, params=params_80, entropy=None):
        SPAKE2.__init__(self, password, "Q", params, entropy)


# add ECC version for smaller messages/storage
# consider timing attacks
# try for compatibility with Boneh's JS version
