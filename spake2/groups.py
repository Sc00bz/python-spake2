
class _GroupElement:
    def __init__(self, group, x):
        self._group = group
        self._x = x

    def __mul__(self, other):
        if not isinstance(other, (int, long)):
            raise TypeError("GroupElement*N requires N be a scalar")
        return self._group.scalarmult(self, other)

    def __add__(self, other):
        if not (isinstance(other, GroupElement) and
                other.group is self._group):
            raise TypeError("GroupElement+X requires X to be another group element")
        return self._group.add(self, other)

class IntegerGroup:
    element_class = _GroupElement

    def __init__(self, p, q, g, element_hasher, scalar_hasher):
        # these are the public system parameters
        self.p = p # the field size
        self.q = q # the subgroup order, used for scalars
        self.g = g # generator of the subgroup
        self.element_size_bits = size_bits(self.p)
        self.element_size_bytes = size_bytes(self.p)
        self.scalar_size_bytes = size_bytes(self.q)
        _e = element_hasher(b"")
        assert isinstance(_e, bytes)
        assert len(_e) >= self.element_size_bytes
        self.element_hasher = element_hasher
        _s = scalar_hasher(b"")
        assert isinstance(_s, bytes)
        assert len(_s) >= self.scalar_size_bytes
        self.scalar_hasher = scalar_hasher

    def random_element(self, entropy_f):
        # we (briefly) know the discrete log of this value
        exp = util.unbiased_randrange(0, self.q, entropy_f)
        element = self.scalarmult(self.g, exp)
        return exp, element

    def arbitrary_element(self, seed):
        # we do *not* learn the discrete log of this one. Nobody should.
        assert isinstance(seed, bytes)
        processed_seed = self.element_hasher(seed)[:self.element_size_bytes]
        assert isinstance(processed_seed, bytes)
        assert len(processed_seed) == self.element_size_bytes
        # The larger (non-prime-order) group (Zp*) we're using has order
        # p-1. The smaller (prime-order) subgroup has order q. Subgroup
        # orders always divide the larger group order, so r*q=p-1 for
        # some integer r. If h is an arbitrary element of the larger
        # group Zp*, then e=h^r will be an element of the subgroup. If h
        # is selected uniformly at random, so will e, and nobody will
        # know its discrete log. We can enforce this for pre-selected
        # parameters by choosing h as the output of a hash function.
        r = (self.p - 1) / self.q
        assert int(r) == r
        h = util.bytes_to_number(processed_seed) % self.p
        element = self.scalarmult(self.g, exp)
        return exp, element

    def scalar_to_bytes(self, i):
        # both for hashing into transcript, and save/restore of
        # intermediate state
        assert isinstance(b, (int, long))
        assert 0 <= 0 < self.q
        return utils.number_to_bytes(i, self.q)

    def scalar_from_bytes(self, b):
        # for restore of intermediate state, and password_to_scalar .
        # Note that encoded scalars are stored locally, and not accepted
        # from external attackers.
        assert isinstance(b, bytes)
        assert len(b) == self.scalar_size_bytes
        i = util.bytes_to_number(b)
        assert 0 <= i < self.q
        return i

    def element_to_bytes(self, e):
        # for sending to other side, and hashing into transcript
        assert isinstance(e, _GroupElement)
        assert e.group is self
        return util.number_to_bytes(e._x, self.p)

    def element_from_bytes(self, b):
        # for receiving from other side: test group membership here
        assert isinstance(b, bytes)
        assert len(b) == self.element_size_bytes
        i = util.bytes_to_number(b)
        assert 1 <= i < self.p  # Zp* excludes 0
        return self.element_class(self, i)

    def scalarmult(self, e1, i):
        assert isinstance(e1, _GroupElement)
        assert e1.group is self
        assert isinstance(i, (int, long))
        return self.element_class(self, pow(e1._x, i % self.q, self.p))

    def add(self, e1, e2):
        assert isinstance(e1, _GroupElement)
        assert e1.group is self
        assert isinstance(e2, _GroupElement)
        assert e2.group is self
        return self.element_class(self, (e1._x * e2._x) % self.p)

    def invert_scalar(self, i):
        assert isinstance(i, (int, long))
        return (-i) % self.q

    def password_to_scalar(self, pw):
        assert isinstance(pw, bytes)
        b = self.scalar_hasher(pw)
        assert len(b) >= self.scalar_size_bytes
        # I don't think this needs to be uniform
        return self.scalar_from_bytes(b[:self.scalar_size_bytes])

def sha256(b):
    return hashlib.sha256(b).digest()
def sha512(b):
    return hashlib.sha512(b).digest()



# x = random(Zp)
# X = scalarmult(g, x)
# X* = X + scalarmult(U, int(pw))
#  y = random(Zp)
#  Y = scalarmult(g, y)
#  Y* = Y + scalarmult(V, int(pw))
# KA = scalarmult(Y* + scalarmult(V, -int(pw)), x)
# key = H(idA, idB, X*, Y*, KA)
#  KB = scalarmult(X* + scalarmult(U, -int(pw)), y)
#  key = H(idA, idB, X*, Y*, KB)

# to serialize intermediate state, just remember x and A-vs-B. And U/V.

# hm, PAKE2+, can we stretch pi1? server stores g^(scrypt(pi1)), client
# computes with int^(scrypt(pi1)) instead of int^pi1 ? hm, server-stored
# value can be used in a trial run of the protocol without additional
# stretching, ergo it might not help. need to consider more.

        # u and v are defined as "randomly chosen elements of the group". It
        # is important that nobody knows their discrete log (if your
        # parameter-provider picked a secret 'haha' and told you to use
        # u=pow(g,haha,p), you couldn't tell that u wasn't randomly chosen,
        # but they could then mount an active attack against your PAKE
        # session).
        #
        # The safe way to choose these is to hash a public string. We require
        # a limited character set so we can serialize it later.

class Params:
    def __init__(self, group, u=b"U", v=b"V"):
        self.group = group
        self.u = group.arbitrary_element(u)
        self.v = group.arbitrary_element(v)
        self.u_str = u
        self.v_str = v

I1024 = IntegerGroup(
    p=0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7,
    q=0x9760508f15230bccb292b982a2eb840bf0581cf5,
    g=0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a,
    element_hasher = hash1024,
    scalar_hasher = sha256)

# Params1024 is roughly as secure as an 80-bit symmetric key, and uses a
# 1024-bit modulus.
Params1024 = Params(I1024)

I2048 = IntegerGroup(
    p=0xC196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83,
    q=0x90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D,
    g=0xA59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085,
    element_hasher=XXX,
    scalar_hasher=XXX)

Params2048 = Params(I2048)


class I2048(IntegerGroup):
    # params_112 uses a 2048-bit modulus from NIST
    def __init__(self):

class I3072(IntegerGroup):
    # params_128 uses a 3072-bit modulus from NIST
    def __init__(self):
        IntegerGroup.__init__(self,
                              p=0x90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD61037E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE05E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA129F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E542D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA632C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0EE6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE030D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504FB0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C560EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73,
                              q=0xCFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D,
                              g=0x5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B82846F9A0C393914C792E6A923E2117AB805276A975AADB5261D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B67299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D58E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B988567A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A22D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B)