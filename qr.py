# -*- coding: utf-8 -*-
"""純 Python QR Code 編碼器（僅依標準函式庫），實作 ISO/IEC 18004 子集。

支援版本 1~10、英數位元與位元組模式、L/M/Q/H 錯誤糾正、8 種遮罩自動選擇。
回傳布林矩陣；由呼叫者繪製（Pillow PNG / SVG / PDF 方塊）。
未實作：結構化補充（Appendix）、Kanji 模式、ECI。本系統不需用到。
"""

# --------------------------------------------------------------------------
# GF(256) 與 Reed-Solomon
# --------------------------------------------------------------------------
def _build_gf_tables():
    exp = [0] * 512
    log = [0] * 256
    x = 1
    for i in range(255):
        exp[i] = x
        log[x] = i
        x <<= 1
        if x & 0x100:
            x ^= 0x11D
    for i in range(255, 512):
        exp[i] = exp[i - 255]
    return exp, log


EXP, LOG = _build_gf_tables()


def _gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return EXP[LOG[a] + LOG[b]]


def _gf_pow(a, n):
    if n == 0:
        return 1
    return EXP[(LOG[a] * n) % 255]


def _gf_poly_mul(p, q):
    r = [0] * (len(p) + len(q) - 1)
    for j in range(len(q)):
        for i in range(len(p)):
            r[i + j] ^= _gf_mul(p[i], q[j])
    return r


def _rs_encode(data, numec):
    gen = [1]
    for i in range(numec):
        gen = _gf_poly_mul(gen, [1, _gf_pow(2, i)])
    msg = list(data) + [0] * numec
    for i in range(len(data)):
        coef = msg[i]
        if coef:
            for j in range(1, len(gen)):
                msg[i + j] ^= _gf_mul(gen[j], coef)
    return msg[-numec:]


# --------------------------------------------------------------------------
# 編碼輔助
# --------------------------------------------------------------------------
_ALPHANUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
_ALPHANUM_VAL = {ch: i for i, ch in enumerate(_ALPHANUM)}


def _encode_alphanum(text):
    bits = []
    i = 0
    n = len(text)
    while i < n:
        v1 = _ALPHANUM_VAL.get(text[i])
        if v1 is None:
            return None
        if i + 1 < n:
            v2 = _ALPHANUM_VAL.get(text[i + 1])
            if v2 is not None:
                val = v1 * 45 + v2
                bits.extend((val >> j) & 1 for j in range(10, -1, -1))
                i += 2
                continue
        bits.extend((v1 >> j) & 1 for j in range(5, -1, -1))
        i += 1
    return bits


def _encode_byte(text):
    return [b for ch in text for b in format(ord(ch), "08b")]


# 版本 1~10：各等級 EC 碼字數 / 資料碼字數
_EC_COUNT = {
    1: {"L": 7, "M": 10, "Q": 13, "H": 17},
    2: {"L": 10, "M": 16, "Q": 22, "H": 28},
    3: {"L": 15, "M": 26, "Q": 36, "H": 44},
    4: {"L": 20, "M": 36, "Q": 52, "H": 64},
    5: {"L": 26, "M": 48, "Q": 72, "H": 88},
    6: {"L": 36, "M": 64, "Q": 88, "H": 98},
    7: {"L": 48, "M": 72, "Q": 106, "H": 122},
    8: {"L": 60, "M": 88, "Q": 130, "H": 150},
    9: {"L": 72, "M": 106, "Q": 152, "H": 174},
    10: {"L": 88, "M": 132, "Q": 176, "H": 204},
}
_DATA_COUNT = {
    1: {"L": 19, "M": 16, "Q": 13, "H": 9},
    2: {"L": 34, "M": 28, "Q": 22, "H": 16},
    3: {"L": 55, "M": 44, "Q": 37, "H": 27},
    4: {"L": 80, "M": 64, "Q": 48, "H": 34},
    5: {"L": 108, "M": 84, "Q": 62, "H": 42},
    6: {"L": 136, "M": 112, "Q": 88, "H": 62},
    7: {"L": 156, "M": 130, "Q": 102, "H": 76},
    8: {"L": 172, "M": 148, "Q": 116, "H": 84},
    9: {"L": 196, "M": 168, "Q": 130, "H": 96},
    10: {"L": 242, "M": 202, "Q": 158, "H": 116},
}


def _version_info(version):
    if version < 7:
        return None
    poly = version << 12
    for i in range(17, 11, -1):
        if (poly >> i) & 1:
            poly ^= 0x1F25 << (i - 12)
    return ((version << 12) | poly) & 0x3FFFF


_FORMAT_POLY = 0x537
_FORMAT_XOR = 0x5412


def _format_bits(ec_level, mask):
    level_bits = {"L": 1, "M": 0, "Q": 3, "H": 2}[ec_level]
    data = (level_bits << 3) | mask
    poly = data << 10
    for i in range(14, 9, -1):
        if (poly >> i) & 1:
            poly ^= _FORMAT_POLY << (i - 10)
    val = ((data << 10) | poly) ^ _FORMAT_XOR
    return [(val >> i) & 1 for i in range(14, -1, -1)]


def _align_positions(version):
    table = {
        1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
        6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42],
        9: [6, 26, 46], 10: [6, 28, 50],
    }
    return table[version]


def _choose_version(bit_len, ec_level):
    for v in range(1, 11):
        if bit_len <= _DATA_COUNT[v][ec_level] * 8:
            return v
    return 10


# --------------------------------------------------------------------------
# 矩陣建構（func 與 data 格嚴格分離）
# --------------------------------------------------------------------------
def _build_matrix(version, ec_level, data_bits):
    size = 4 * version + 17
    cells = [[None] * size for _ in range(size)]
    func = [[False] * size for _ in range(size)]

    def put_func(r, c, val):
        cells[r][c] = val
        func[r][c] = True

    def put_finder(r, c):
        for i in range(7):
            for j in range(7):
                edge = i in (0, 6) or j in (0, 6)
                center = i == 3 and j == 3
                put_func(r + i, c + j, edge or center)

    put_finder(0, 0)
    put_finder(0, size - 7)
    put_finder(size - 7, 0)
    for i in range(size):
        put_func(7, i, False)
        put_func(i, 7, False)
        put_func(size - 8, i, False)
        put_func(i, size - 8, False)

    # 定位圖樣
    aligns = _align_positions(version)
    if len(aligns) > 1:
        for r in aligns:
            for c in aligns:
                if (r <= 8 and c <= 8) or (r <= 8 and c >= size - 9) or (r >= size - 9 and c <= 8):
                    continue
                for i in range(-2, 3):
                    for j in range(-2, 3):
                        val = abs(i) == 2 or abs(j) == 2 or (i == 0 and j == 0)
                        put_func(r + i, c + j, val)

    # 計時圖樣
    for i in range(8, size - 8):
        put_func(i, 6, (i % 2 == 0))
        put_func(6, i, (i % 2 == 0))

    # 版本資訊（7~10）
    vi = _version_info(version)
    if vi is not None:
        vbits = [(vi >> i) & 1 for i in range(17, -1, -1)]
        idx = 0
        for j in range(3):
            for i in range(6):
                put_func(size - 1 - i, size - 7 + j, vbits[idx])
                idx += 1
        idx = 0
        for i in range(6):
            for j in range(3):
                put_func(size - 7 + j, i, vbits[idx])
                idx += 1

    # 資料填入（zigzag，從右下往上；只填非功能格）
    bit_idx = 0
    up = True
    row = size - 1
    col = size - 1
    while col > 0:
        if col == 6:
            col -= 1
        while 0 <= row < size:
            for ccol in (col, col - 1):
                if ccol < 0:
                    continue
                if not func[row][ccol]:
                    if bit_idx < len(data_bits):
                        cells[row][ccol] = data_bits[bit_idx]
                        bit_idx += 1
                    else:
                        cells[row][ccol] = False
            row += -1 if up else 1
        up = not up
        row += -1 if up else 1
        col -= 2

    # 格式資訊位置（功能格，encode() 會覆寫）
    fmt_cells = []
    for i in range(8):
        fmt_cells.append((i, 8))
        fmt_cells.append((8, size - 1 - i))
    fmt_cells.append((7, 8))
    fmt_cells.append((8, 7))
    for i in range(7):
        fmt_cells.append((size - 1 - i, 8))
        fmt_cells.append((8, i))
    for (r, c) in fmt_cells:
        put_func(r, c, False)  # 佔位

    return cells, func, size, fmt_cells


def _apply_mask(cells, func, mask, size):
    for r in range(size):
        for c in range(size):
            if func[r][c]:
                continue
            cond = False
            if mask == 0:
                cond = (r + c) % 2 == 0
            elif mask == 1:
                cond = r % 2 == 0
            elif mask == 2:
                cond = c % 3 == 0
            elif mask == 3:
                cond = (r + c) % 3 == 0
            elif mask == 4:
                cond = (r // 2 + c // 3) % 2 == 0
            elif mask == 5:
                cond = (r * c) % 2 + (r * c) % 3 == 0
            elif mask == 6:
                cond = ((r * c) % 2 + (r * c) % 3) % 2 == 0
            elif mask == 7:
                cond = ((r + c) % 2 + (r * c) % 3) % 2 == 0
            if cond:
                cells[r][c] = not cells[r][c]
    return cells


def _mask_penalty(matrix):
    size = len(matrix)
    penalty = 0
    # 1. 同色連線（直/橫）
    for r in range(size):
        for c in range(size):
            color = matrix[r][c]
            for dr, dc in ((0, 1), (1, 0)):
                length = 1
                rr, cc = r + dr, c + dc
                while 0 <= rr < size and 0 <= cc < size and matrix[rr][cc] == color:
                    length += 1
                    rr += dr
                    cc += dc
                if length >= 5:
                    penalty += 3 + (length - 5)
    # 2. 2x2 相同色區塊
    for r in range(size - 1):
        for c in range(size - 1):
            if (matrix[r][c] == matrix[r + 1][c] == matrix[r][c + 1] == matrix[r + 1][c + 1]):
                penalty += 3
    # 3. 1:1:3:1:1 模式
    pat1 = [True, False, True, True, True, False, True]
    pat2 = [False, True, False, False, False, True, False]
    for r in range(size):
        for c in range(size - 6):
            if matrix[r][c:c + 7] == pat1 or matrix[r][c:c + 7] == pat2:
                penalty += 40
    for c in range(size):
        for r in range(size - 6):
            seg = [matrix[r + i][c] for i in range(7)]
            if seg == pat1 or seg == pat2:
                penalty += 40
    # 4. 暗模組比例
    dark = sum(1 for r in range(size) for c in range(size) if matrix[r][c])
    pct = dark * 100 // (size * size)
    penalty += ((pct - 50) // 5) * 10
    return penalty


# --------------------------------------------------------------------------
# 對外 API
# --------------------------------------------------------------------------
def encode(data, ec_level="M", version=None):
    """編碼文字為 QR 矩陣。回傳 (matrix, version, size, ec_level, mask)。"""
    data = data or ""
    bits = _encode_alphanum(data)
    mode = "alphanum"
    if bits is None:
        bits = _encode_byte(data)
        mode = "byte"
    if version is None:
        version = _choose_version(len(bits), ec_level)
    cc_len = 9 if (mode == "alphanum" and version <= 9) else (
        11 if mode == "alphanum" else (8 if version <= 9 else 16))
    mode_bits = "0010" if mode == "alphanum" else "0100"
    header = [int(x) for x in (mode_bits + format(len(data), "0{}b".format(cc_len)))]
    data_bits = header + bits
    cap = _DATA_COUNT[version][ec_level] * 8
    if len(data_bits) < cap:
        data_bits += [0] * min(4, cap - len(data_bits))
    while len(data_bits) % 8 != 0:
        data_bits.append(0)
    fillers = [0b11101100, 0b00010001]
    while len(data_bits) < cap:
        fc = fillers[(len(data_bits) // 8) % 2]
        data_bits += [(fc >> (7 - i)) & 1 for i in range(8)]
    data_bits = data_bits[:cap]

    codewords = [int("".join(str(b) for b in data_bits[i:i + 8]), 2)
                 for i in range(0, len(data_bits), 8)]
    ec = _EC_COUNT[version][ec_level]
    total = cap // 8
    dpc = total - ec
    if dpc <= 0:
        dpc = 1
    final = codewords + _rs_encode(codewords[:dpc], ec)
    final_bits = [b for cw in final for b in format(cw, "08b")]

    best = None
    for mask in range(8):
        cells, func, size, fmt_cells = _build_matrix(version, ec_level, final_bits)
        trial = [row[:] for row in cells]
        funcc = [row[:] for row in func]
        _apply_mask(trial, funcc, mask, size)
        fb = _format_bits(ec_level, mask)
        for (r, c), bit in zip(fmt_cells, fb):
            trial[r][c] = bit
        pen = _mask_penalty(trial)
        if best is None or pen < best[0]:
            best = (pen, mask, trial, size)
    _, mask, matrix, size = best
    return matrix, version, size, ec_level, mask


def matrix_to_svg(matrix, module_size=4, border=2):
    size = len(matrix)
    total = size + 2 * border
    lines = ['<svg xmlns="http://www.w3.org/2000/svg" width="{}" height="{}" viewBox="0 0 {} {}">'.format(
        total * module_size, total * module_size, total, total)]
    lines.append('<rect width="{}" height="{}" fill="white"/>'.format(total * module_size, total * module_size))
    for r in range(size):
        for c in range(size):
            if matrix[r][c]:
                x = (c + border) * module_size
                y = (r + border) * module_size
                lines.append('<rect x="{}" y="{}" width="{}" height="{}" fill="black"/>'.format(
                    x, y, module_size, module_size))
    lines.append('</svg>')
    return "\n".join(lines)


def matrix_to_png_bytes(matrix, module_size=4, border=2):
    """回傳 PNG bytes（需 Pillow）。"""
    from PIL import Image
    import io
    size = len(matrix)
    total = size + 2 * border
    img = Image.new("RGB", (total * module_size, total * module_size), "white")
    px = img.load()
    for r in range(size):
        for c in range(size):
            if matrix[r][c]:
                for dy in range(module_size):
                    for dx in range(module_size):
                        px[(c + border) * module_size + dx, (r + border) * module_size + dy] = (0, 0, 0)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


if __name__ == "__main__":
    import sys
    text = sys.argv[1] if len(sys.argv) > 1 else "SA01"
    m, v, s, ec, mask = encode(text, "M")
    print("QR {} v{} ec{} mask{} size={}x{}".format(text, v, ec, mask, s, s))
    print(matrix_to_svg(m, module_size=2, border=1))
