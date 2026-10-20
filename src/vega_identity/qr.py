"""qr.py - a small QR code encoder (byte mode, error-correction level M, versions 1 to 9, so up to 180 bytes) so the authenticator-app set-up code needs no outside library.

  encode(text) -> a square grid of booleans (True = dark), 4 modules of quiet zone NOT included
  to_svg(grid, scale) -> an SVG string with its own quiet zone;  to_text(grid) -> block characters for a terminal
The set-up URI contains the one-time-code secret: show the code only on the screen of the person enrolling, never log it, never send it anywhere.
Tested against OpenCV's QR decoder when that is installed. Not a general QR library: no numeric/alphanumeric/kanji modes, no Micro QR, no structured append."""

# level M: (total codewords, EC codewords per block, [(blocks, data codewords per block), ...])
_M = {1: (26, 10, [(1, 16)]), 2: (44, 16, [(1, 28)]), 3: (70, 26, [(1, 44)]), 4: (100, 18, [(2, 32)]), 5: (134, 24, [(2, 43)]),
      6: (172, 16, [(4, 27)]), 7: (196, 18, [(4, 31)]), 8: (242, 22, [(2, 38), (2, 39)]), 9: (292, 22, [(3, 36), (2, 37)])}
_ALIGN = {1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30], 6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46]}
MAX_BYTES = 180


class QRRefused(ValueError):
    pass


_EXP, _LOG = [0] * 512, [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]


def _mul(a, b):
    return 0 if a == 0 or b == 0 else _EXP[_LOG[a] + _LOG[b]]


def _rs(data, n):
    gen = [1]
    for i in range(n):
        nxt = [0] * (len(gen) + 1)
        for j, c in enumerate(gen):
            nxt[j] ^= c
            nxt[j + 1] ^= _mul(c, _EXP[i])
        gen = nxt
    rem = [0] * n
    for b in data:
        f = b ^ rem[0]
        rem = rem[1:] + [0]
        for j in range(n):
            rem[j] ^= _mul(gen[j + 1], f)
    return rem


def _bits(text: bytes, version: int):
    total, ec, groups = _M[version]
    cap = sum(b * d for b, d in groups)
    bits = "0100" + format(len(text), "08b") + "".join(format(b, "08b") for b in text)
    bits += "0" * min(4, cap * 8 - len(bits))
    bits += "0" * (-len(bits) % 8)
    data = [int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)]
    pad, i = [0xEC, 0x11], 0
    while len(data) < cap:
        data.append(pad[i % 2])
        i += 1
    blocks, pos = [], 0
    for nb, dc in groups:
        for _ in range(nb):
            blocks.append(data[pos:pos + dc])
            pos += dc
    ecs = [_rs(b, ec) for b in blocks]
    out = []
    for i in range(max(len(b) for b in blocks)):
        for b in blocks:
            if i < len(b):
                out.append(b[i])
    for i in range(ec):
        for e in ecs:
            out.append(e[i])
    return "".join(format(b, "08b") for b in out) + "0" * (7 if 2 <= version <= 6 else 0)      # remainder bits


def _bch(value, poly, bits):
    v = value << bits
    plen = poly.bit_length()
    while v.bit_length() >= plen:
        v ^= poly << (v.bit_length() - plen)
    return (value << bits) | v


def _format_bits(mask):
    return _bch((0b00 << 3) | mask, 0b10100110111, 10) ^ 0b101010000010010          # level M = 00


def _version_bits(version):
    return _bch(version, 0b1111100100101, 12)


def _build(version, bits, mask):
    n = 17 + 4 * version
    g = [[None] * n for _ in range(n)]
    func = [[False] * n for _ in range(n)]

    def put(r, c, v, f=True):
        g[r][c] = v
        func[r][c] = f
    for (r0, c0) in ((0, 0), (0, n - 7), (n - 7, 0)):
        for dr in range(-1, 8):
            for dc in range(-1, 8):
                r, c = r0 + dr, c0 + dc
                if 0 <= r < n and 0 <= c < n:
                    inside = 0 <= dr <= 6 and 0 <= dc <= 6
                    dark = inside and (dr in (0, 6) or dc in (0, 6) or (2 <= dr <= 4 and 2 <= dc <= 4))
                    put(r, c, dark)
    for i in range(8, n - 8):
        put(6, i, i % 2 == 0)
        put(i, 6, i % 2 == 0)
    pts = _ALIGN[version]
    for r in pts:
        for c in pts:
            if (r, c) in ((6, 6), (6, pts[-1]), (pts[-1], 6)):          # these three would sit on a finder pattern
                continue
            for dr in range(-2, 3):
                for dc in range(-2, 3):
                    put(r + dr, c + dc, max(abs(dr), abs(dc)) != 1)
    for i in range(9):
        if not func[8][i]:
            put(8, i, False)
        if not func[i][8]:
            put(i, 8, False)
    for i in range(8):
        put(8, n - 1 - i, False)
        put(n - 1 - i, 8, False)
    put(n - 8, 8, True)
    if version >= 7:
        vb = _version_bits(version)
        for i in range(18):
            bit = bool((vb >> i) & 1)
            put(i // 3, n - 11 + i % 3, bit)
            put(n - 11 + i % 3, i // 3, bit)
    # data, zigzag from the bottom right
    idx, up, c = 0, True, n - 1
    while c > 0:
        if c == 6:
            c -= 1
        rows = range(n - 1, -1, -1) if up else range(n)
        for r in rows:
            for cc in (c, c - 1):
                if not func[r][cc]:
                    bit = idx < len(bits) and bits[idx] == "1"
                    idx += 1
                    m = [(r + cc) % 2 == 0, r % 2 == 0, cc % 3 == 0, (r + cc) % 3 == 0, (r // 2 + cc // 3) % 2 == 0,
                         (r * cc) % 2 + (r * cc) % 3 == 0, ((r * cc) % 2 + (r * cc) % 3) % 2 == 0, ((r + cc) % 2 + (r * cc) % 3) % 2 == 0][mask]
                    g[r][cc] = bit != m
        up = not up
        c -= 2
    fb = _format_bits(mask)
    for i in range(15):
        bit = bool((fb >> i) & 1)
        if i < 6:
            g[i][8] = bit
        elif i == 6:
            g[7][8] = bit
        elif i == 7:
            g[8][8] = bit
        elif i == 8:
            g[8][7] = bit
        else:
            g[8][14 - i] = bit
        if i < 8:
            g[8][n - 1 - i] = bit
        else:
            g[n - 15 + i][8] = bit
    return g


def _penalty(g):
    n = len(g)
    p = 0
    for rows in (g, [list(col) for col in zip(*g)]):
        for row in rows:
            run = 1
            for i in range(1, n):
                if row[i] == row[i - 1]:
                    run += 1
                else:
                    if run >= 5:
                        p += 3 + run - 5
                    run = 1
            if run >= 5:
                p += 3 + run - 5
            s = "".join("1" if x else "0" for x in row)
            p += 40 * (s.count("10111010000") + s.count("00001011101"))
    for r in range(n - 1):
        for c in range(n - 1):
            if g[r][c] == g[r + 1][c] == g[r][c + 1] == g[r + 1][c + 1]:
                p += 3
    dark = sum(sum(1 for x in row if x) for row in g)
    p += 10 * (abs(dark * 100 // (n * n) - 50) // 5)
    return p


def encode(text):
    if not isinstance(text, str):
        raise QRRefused("text is a string")
    raw = text.encode("utf-8")
    if not raw or len(raw) > MAX_BYTES:
        raise QRRefused("1 to %d bytes" % MAX_BYTES)
    version = next((v for v in range(1, 10) if len(raw) <= sum(b * d for b, d in _M[v][2]) - 2), None)
    if version is None:
        raise QRRefused("too long")
    bits = _bits(raw, version)
    best = min((_build(version, bits, m) for m in range(8)), key=_penalty)
    return [[bool(x) for x in row] for row in best]


def to_svg(grid, scale: int = 6) -> str:
    n = len(grid)
    q = 4
    size = (n + 2 * q) * scale
    rects = "".join('<rect x="%d" y="%d" width="%d" height="%d"/>' % ((c + q) * scale, (r + q) * scale, scale, scale) for r, row in enumerate(grid) for c, v in enumerate(row) if v)
    return ('<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d"><rect width="100%%" height="100%%" fill="#fff"/><g fill="#000">%s</g></svg>'
            % (size, size, size, size, rects))


def to_text(grid) -> str:
    return "\n".join("".join("██" if v else "  " for v in row) for row in grid)
