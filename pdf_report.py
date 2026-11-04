#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
極簡 PDF 報表產生器（只用 Python 標準函式庫）。

- 內嵌專案內的 Noto Sans TC 子集字型，支援繁體中文。
- 提供 `build_table_pdf()`：標題、說明、表格、頁碼，自動換頁。
- 適合列印 A4 報表；不依賴 reportlab / fpdf / weasyprint。
"""

import os
import struct
import zlib

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_FONT = os.path.join(BASE_DIR, "vendor", "NotoSansTC-Regular-subset.ttf")

A4_PORTRAIT = (595.28, 841.89)
A4_LANDSCAPE = (841.89, 595.28)


# ---------------------------------------------------------------------------
# TrueType 字型解析
# ---------------------------------------------------------------------------

def _u16(data, offset):
    return struct.unpack_from(">H", data, offset)[0]


def _s16(data, offset):
    return struct.unpack_from(">h", data, offset)[0]


def _u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


class TrueTypeFont:
    def __init__(self, path):
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.path = path
        self.tables = {}
        self._parse_directory()
        self._parse_head()
        self._parse_hhea()
        self._parse_maxp()
        self._parse_hmtx()
        self._parse_cmap()
        self._width_cache = {}

    def _parse_directory(self):
        data = self.data
        if data[:4] == b"ttcf":
            raise ValueError("不支援 TTC 字型，請使用 TTF")
        num_tables = _u16(data, 4)
        for i in range(num_tables):
            pos = 12 + i * 16
            tag = data[pos:pos + 4].decode("latin-1")
            offset = _u32(data, pos + 8)
            length = _u32(data, pos + 12)
            self.tables[tag] = (offset, length)
        for required in ("head", "hhea", "maxp", "hmtx", "cmap"):
            if required not in self.tables:
                raise ValueError("字型缺少必要表格：%s" % required)

    def _table(self, tag):
        offset, length = self.tables[tag]
        return self.data[offset:offset + length]

    def _parse_head(self):
        head = self._table("head")
        self.units_per_em = _u16(head, 18)
        self.x_min = _s16(head, 36)
        self.y_min = _s16(head, 38)
        self.x_max = _s16(head, 40)
        self.y_max = _s16(head, 42)
        if self.units_per_em <= 0:
            self.units_per_em = 1000

    def _parse_hhea(self):
        hhea = self._table("hhea")
        self.ascent = _s16(hhea, 4)
        self.descent = _s16(hhea, 6)
        self.num_hmetrics = _u16(hhea, 34)

    def _parse_maxp(self):
        maxp = self._table("maxp")
        self.num_glyphs = _u16(maxp, 4)

    def _parse_hmtx(self):
        hmtx = self._table("hmtx")
        advances = []
        for i in range(self.num_hmetrics):
            advances.append(_u16(hmtx, i * 4))
        if advances:
            last = advances[-1]
            while len(advances) < self.num_glyphs:
                advances.append(last)
        self.advances = advances

    def _parse_cmap(self):
        cmap = self._table("cmap")
        num = _u16(cmap, 2)
        subtables = []
        for i in range(num):
            pos = 4 + i * 8
            platform = _u16(cmap, pos)
            encoding = _u16(cmap, pos + 2)
            offset = _u32(cmap, pos + 4)
            subtables.append((platform, encoding, offset))

        # 優先 format 12（完整 Unicode），其次 format 4（BMP）
        chosen = None
        for platform, encoding, offset in subtables:
            if platform == 3 and encoding == 10:
                chosen = (offset, 12)
                break
        if chosen is None:
            for platform, encoding, offset in subtables:
                if (platform == 3 and encoding == 1) or (platform == 0 and encoding in (3, 4)):
                    chosen = (offset, 4)
                    break
        if chosen is None:
            raise ValueError("字型缺少可用的 Unicode cmap")

        offset, fmt = chosen
        self.cmap = {}
        if fmt == 12:
            self._parse_cmap12(cmap, offset)
        else:
            self._parse_cmap4(cmap, offset)

    def _parse_cmap12(self, cmap, offset):
        if _u16(cmap, offset) != 12:
            raise ValueError("cmap format 12 解析失敗")
        n_groups = _u32(cmap, offset + 12)
        pos = offset + 16
        for _ in range(n_groups):
            start = _u32(cmap, pos)
            end = _u32(cmap, pos + 4)
            start_gid = _u32(cmap, pos + 8)
            pos += 12
            for cp in range(start, end + 1):
                self.cmap[cp] = start_gid + (cp - start)

    def _parse_cmap4(self, cmap, offset):
        if _u16(cmap, offset) != 4:
            raise ValueError("cmap format 4 解析失敗")
        seg_count = _u16(cmap, offset + 6) // 2
        end_pos = offset + 14
        start_pos = end_pos + seg_count * 2 + 2
        delta_pos = start_pos + seg_count * 2
        range_pos = delta_pos + seg_count * 2
        for i in range(seg_count):
            end = _u16(cmap, end_pos + i * 2)
            start = _u16(cmap, start_pos + i * 2)
            delta = _s16(cmap, delta_pos + i * 2)
            range_offset = _u16(cmap, range_pos + i * 2)
            if start == 0xFFFF:
                continue
            for cp in range(start, end + 1):
                if range_offset == 0:
                    gid = (cp + delta) & 0xFFFF
                else:
                    addr = range_pos + i * 2 + range_offset + (cp - start) * 2
                    if addr + 1 >= len(cmap):
                        continue
                    gid = _u16(cmap, addr)
                    if gid:
                        gid = (gid + delta) & 0xFFFF
                if gid:
                    self.cmap[cp] = gid

    def gid(self, codepoint):
        return self.cmap.get(codepoint, 0)

    def width(self, gid):
        """回傳 PDF 文字寬度（千分之一 em）。"""
        if gid in self._width_cache:
            return self._width_cache[gid]
        if 0 <= gid < len(self.advances):
            value = self.advances[gid] * 1000.0 / self.units_per_em
        else:
            value = 1000.0
        self._width_cache[gid] = value
        return value

    def scaled(self, value):
        return value * 1000.0 / self.units_per_em


# ---------------------------------------------------------------------------
# PDF 物件與頁面
# ---------------------------------------------------------------------------

_FONT_CACHE = {}


def _get_font(path):
    font = _FONT_CACHE.get(path)
    if font is None:
        font = TrueTypeFont(path)
        _FONT_CACHE[path] = font
    return font


class Canvas:
    def __init__(self, doc, width, height):
        self.doc = doc
        self.width = width
        self.height = height
        self.ops = []

    def _y(self, y):
        return self.height - y

    def text(self, x, baseline_y, text, size=10, color=(0, 0, 0)):
        if text == "":
            return
        gids = []
        for ch in text:
            gid = self.doc.font.gid(ord(ch))
            if not gid:
                gid = self.doc.fallback_gid
            gids.append(gid)
            self.doc.used_gids.add(gid)
            self.doc.gid_to_char.setdefault(gid, ord(ch))
        hex_text = "".join("%04X" % gid for gid in gids)
        r, g, b = color
        self.ops.append(
            "BT /F1 %.2f Tf %.4f %.4f %.4f rg 1 0 0 1 %.2f %.2f Tm <%s> Tj ET"
            % (size, r, g, b, x, self._y(baseline_y), hex_text)
        )

    def measure(self, text, size=10):
        return sum(self.doc.font.width(self.doc.font.gid(ord(ch)) or self.doc.fallback_gid)
                   for ch in text) * size / 1000.0

    def line(self, x1, y1, x2, y2, width=0.5, color=(0, 0, 0)):
        r, g, b = color
        self.ops.append(
            "%.4f %.4f %.4f RG %.2f w %.2f %.2f m %.2f %.2f l S"
            % (r, g, b, width, x1, self._y(y1), x2, self._y(y2))
        )

    def rect(self, x, y, width, height, fill=None, stroke=None, line_width=0.5):
        if fill:
            r, g, b = fill
            self.ops.append(
                "%.4f %.4f %.4f rg %.2f %.2f %.2f %.2f re f"
                % (r, g, b, x, self._y(y + height), width, height)
            )
        if stroke:
            r, g, b = stroke
            self.ops.append(
                "%.4f %.4f %.4f RG %.2f w %.2f %.2f %.2f %.2f re S"
                % (r, g, b, line_width, x, self._y(y + height), width, height)
            )


class PDFDocument:
    def __init__(self, font_path=DEFAULT_FONT):
        self.font = _get_font(font_path)
        self.fallback_gid = self.font.gid(ord("?")) or 0
        self.used_gids = set()
        self.gid_to_char = {}
        self.pages = []

    def add_page(self, width, height):
        canvas = Canvas(self, width, height)
        self.pages.append(canvas)
        return canvas

    def _compress(self, data):
        return zlib.compress(data)

    def _stream(self, body, extra=""):
        compressed = self._compress(body)
        return (
            "<< /Length %d /Filter /FlateDecode%s >>\nstream\n" % (len(compressed), extra)
        ).encode("ascii") + compressed + b"\nendstream"

    def _to_unicode_cmap(self):
        items = sorted(self.gid_to_char.items())
        lines = [
            "/CIDInit /ProcSet findresource begin",
            "12 dict begin",
            "begincmap",
            "/CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def",
            "/CMapName /Adobe-Identity-UCS def",
            "/CMapType 2 def",
            "1 begincodespacerange",
            "<0000> <FFFF>",
            "endcodespacerange",
        ]
        for start in range(0, len(items), 100):
            chunk = items[start:start + 100]
            lines.append("%d beginbfchar" % len(chunk))
            for gid, cp in chunk:
                if cp <= 0xFFFF:
                    target = "%04X" % cp
                else:
                    value = cp - 0x10000
                    target = "%04X%04X" % (0xD800 + (value >> 10), 0xDC00 + (value & 0x3FF))
                lines.append("<%04X> <%s>" % (gid, target))
            lines.append("endbfchar")
        lines.extend([
            "endcmap",
            "CMapName currentdict /CMap defineresource pop",
            "end",
            "end",
        ])
        return "\n".join(lines).encode("ascii")

    def build(self):
        # 先確保頁碼物件編號：1 catalog、2 pages、3 Type0、4 CIDFont、
        # 5 FontDescriptor、6 FontFile2、7 ToUnicode，之後才是頁面與內容。
        font = self.font
        font_file = font.data
        font_stream = self._stream(font_file, " /Length1 %d" % len(font_file))
        tounicode = self._stream(self._to_unicode_cmap())

        used = sorted(g for g in self.used_gids if g > 0)
        w_parts = ["%d [%d]" % (gid, round(font.width(gid))) for gid in used]
        widths = "[%s]" % " ".join(w_parts) if w_parts else "[]"

        font_bbox = "[%d %d %d %d]" % (
            round(font.scaled(font.x_min)),
            round(font.scaled(font.y_min)),
            round(font.scaled(font.x_max)),
            round(font.scaled(font.y_max)),
        )
        ascent = round(font.scaled(font.ascent))
        descent = round(font.scaled(font.descent))
        cap_height = max(1, round(ascent * 0.7))

        cidfont = (
            "<< /Type /Font /Subtype /CIDFontType2 /BaseFont /NotoSansTC"
            " /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >>"
            " /FontDescriptor 5 0 R /DW 1000 /W %s /CIDToGIDMap /Identity >>"
            % widths
        ).encode("ascii")

        descriptor = (
            "<< /Type /FontDescriptor /FontName /NotoSansTC /Flags 4"
            " /FontBBox %s /ItalicAngle 0 /Ascent %d /Descent %d /CapHeight %d /StemV 80"
            " /FontFile2 6 0 R >>" % (font_bbox, ascent, descent, cap_height)
        ).encode("ascii")

        type0 = (
            "<< /Type /Font /Subtype /Type0 /BaseFont /NotoSansTC /Encoding /Identity-H"
            " /DescendantFonts [4 0 R] /ToUnicode 7 0 R >>"
        ).encode("ascii")

        objects = {
            1: b"<< /Type /Catalog /Pages 2 0 R >>",
            2: None,  # 稍後組
            3: type0,
            4: cidfont,
            5: descriptor,
            6: font_stream,
            7: tounicode,
        }

        next_id = 8
        page_ids = []
        for canvas in self.pages:
            page_id = next_id
            content_id = next_id + 1
            next_id += 2
            page_ids.append(page_id)
            body = ("\n".join(canvas.ops) + "\n").encode("ascii")
            content_stream = self._stream(body)
            objects[content_id] = content_stream
            objects[page_id] = (
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f]"
                " /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>"
                % (canvas.width, canvas.height, content_id)
            ).encode("ascii")

        kids = " ".join("%d 0 R" % pid for pid in page_ids)
        objects[2] = (
            "<< /Type /Pages /Kids [%s] /Count %d >>" % (kids, len(page_ids))
        ).encode("ascii")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = {}
        for obj_id in sorted(objects):
            offsets[obj_id] = len(out)
            out += ("%d 0 obj\n" % obj_id).encode("ascii")
            out += objects[obj_id]
            out += b"\nendobj\n"

        max_id = max(objects)
        xref_pos = len(out)
        out += ("xref\n0 %d\n" % (max_id + 1)).encode("ascii")
        out += b"0000000000 65535 f \n"
        for obj_id in range(1, max_id + 1):
            offset = offsets.get(obj_id, 0)
            out += ("%010d 00000 n \n" % offset).encode("ascii")
        out += ("trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n"
                % (max_id + 1, xref_pos)).encode("ascii")
        return bytes(out)


# ---------------------------------------------------------------------------
# 報表排版
# ---------------------------------------------------------------------------

def _wrap(text, canvas, size, max_width):
    text = "" if text is None else str(text)
    lines = []
    for paragraph in text.split("\n"):
        current = ""
        current_width = 0.0
        for ch in paragraph:
            w = canvas.measure(ch, size)
            if current and current_width + w > max_width:
                lines.append(current)
                current = ch
                current_width = w
            else:
                current += ch
                current_width += w
        lines.append(current)
    return lines or [""]


# 園所全稱：所有報表表頭第一行
SCHOOL_FULL_NAME = "國防部海軍司令部海育員工子女非營利幼兒園（委託社團法人高雄市社區教育協會辦理）"

def build_table_pdf(title, meta_lines, columns, rows, widths=None, landscape=False,
                    font_path=DEFAULT_FONT):
    """產生 PDF bytes。

    columns: 欄位標題清單
    rows:    每列為字串清單，順序對應 columns
    widths:  各欄寬度比例（預設平均）
    """
    page_width, page_height = A4_LANDSCAPE if landscape else A4_PORTRAIT
    margin = 36
    font_size = 9
    header_size = 9
    line_height = font_size * 1.35
    cell_pad = 3
    doc = PDFDocument(font_path)
    canvas = doc.add_page(page_width, page_height)

    usable = page_width - margin * 2
    if not widths:
        widths = [1.0 / len(columns)] * len(columns)
    total = sum(widths)
    widths = [w / total * usable for w in widths]

    top = margin
    # 表頭：園所全稱（第一行，小字）→ 清冊名稱（第二行，大字）→ 列印資訊
    canvas.text(margin, top + 16, SCHOOL_FULL_NAME, size=9, color=(0.25, 0.25, 0.25))
    y = top + 46
    canvas.text(margin, y, title, size=17)
    for line in meta_lines:
        y += 14
        canvas.text(margin, y, line, size=8.5, color=(0.32, 0.32, 0.32))
    y += 12

    header_lines = [_wrap(col, canvas, header_size, w - cell_pad * 2) for col, w in zip(columns, widths)]
    header_height = max(len(lines) for lines in header_lines) * line_height + cell_pad * 2

    def draw_header(canvas, y):
        canvas.rect(margin, y, usable, header_height, fill=(0.92, 0.92, 0.92))
        x = margin
        for lines, w in zip(header_lines, widths):
            ty = y + cell_pad + header_size * 0.9
            for line in lines:
                canvas.text(x + cell_pad, ty, line, size=header_size)
                ty += line_height
            canvas.line(x, y, x, y + header_height, width=0.5)
            x += w
        canvas.line(margin + usable, y, margin + usable, y + header_height, width=0.5)
        canvas.line(margin, y + header_height, margin + usable, y + header_height, width=0.5)
        return y + header_height

    y = draw_header(canvas, y)
    bottom_limit = page_height - 46
    page_index = 0

    for row in rows:
        wrapped = [_wrap(cell, canvas, font_size, w - cell_pad * 2) for cell, w in zip(row, widths)]
        row_height = max(len(lines) for lines in wrapped) * line_height + cell_pad * 2
        if y + row_height > bottom_limit:
            canvas = doc.add_page(page_width, page_height)
            page_index += 1
            y = margin + 10
            y = draw_header(canvas, y)

        x = margin
        for lines, w in zip(wrapped, widths):
            ty = y + cell_pad + font_size * 0.9
            for line in lines:
                canvas.text(x + cell_pad, ty, line, size=font_size)
                ty += line_height
            canvas.line(x, y, x, y + row_height, width=0.35, color=(0.45, 0.45, 0.45))
            x += w
        canvas.line(margin + usable, y, margin + usable, y + row_height, width=0.35, color=(0.45, 0.45, 0.45))
        canvas.line(margin, y + row_height, margin + usable, y + row_height, width=0.35, color=(0.45, 0.45, 0.45))
        y += row_height

    if not rows:
        y += 24
        canvas.text(margin, y, "（目前沒有資料）", size=10, color=(0.4, 0.4, 0.4))

    # 頁尾
    total_pages = len(doc.pages)
    for index, page in enumerate(doc.pages, start=1):
        page.text(margin, page_height - 24, "海育幼兒園圖書管理系統", size=8, color=(0.45, 0.45, 0.45))
        page.text(page_width - margin - 54, page_height - 24,
                  "第 %d / %d 頁" % (index, total_pages), size=8, color=(0.45, 0.45, 0.45))

    return doc.build()
