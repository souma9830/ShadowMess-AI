"""
ShadowMesh — RDP Desktop Bitmap Stub
======================================
Provides a minimal Windows login screen bitmap for the RDP handshake.
The bitmap is a raw 4-byte-per-pixel BGRA buffer sized to the session
dimensions, pre-filled with a Windows 10 login screen grey gradient.

This module is the extension point for future desktop templates:
  - Multiple Windows version themes
  - Dynamic persona-aware wallpapers
  - Recorded session frame playback

Current implementation: solid colour fill that passes RDP bitmap
capability negotiation without requiring any image library.
"""

from __future__ import annotations


# Windows 10 login screen background: dark blue-grey #1a2a3a
_BG_B: int = 0x3A
_BG_G: int = 0x2A
_BG_R: int = 0x1A
_BG_A: int = 0xFF


def generate_login_bitmap(width: int, height: int) -> bytes:
    """
    Return a raw BGRA bitmap of (width x height) pixels representing
    a minimal Windows login screen background.

    The buffer is suitable for embedding in an RDP Bitmap Update PDU
    (uncompressed, 32bpp).  At 1024x768 this is ~3 MB — acceptable for
    a single deception frame sent once per session.
    """
    pixel = bytes([_BG_B, _BG_G, _BG_R, _BG_A])
    return pixel * (width * height)


def get_rdp_bitmap_update(width: int, height: int) -> bytes:
    """
    Build a minimal RDP Bitmap Update PDU wrapping the login bitmap.

    Structure (simplified, uncompressed):
      updateType       : 2 bytes  (0x0001 = UPDATETYPE_BITMAP)
      numberRectangles : 2 bytes  (1)
      --- BitmapData ---
      destLeft         : 2 bytes
      destTop          : 2 bytes
      destRight        : 2 bytes
      destBottom       : 2 bytes
      width            : 2 bytes
      height           : 2 bytes
      bitsPerPixel     : 2 bytes  (32)
      flags            : 2 bytes  (0x0000 = uncompressed)
      bitmapLength     : 2 bytes
      bitmapData       : N bytes

    Note: this PDU is only sent if the attacker's RDP client reaches the
    graphics phase (post-auth).  Current server.py disconnects after
    credential capture, so this function exists for future extension.
    """
    import struct
    bitmap = generate_login_bitmap(width, height)
    bmp_len = len(bitmap)

    header = struct.pack(
        "<HHHHHHHHHH",
        0x0001,          # updateType: UPDATETYPE_BITMAP
        1,               # numberRectangles
        0,               # destLeft
        0,               # destTop
        width,           # destRight
        height,          # destBottom
        width,           # width
        height,          # height
        32,              # bitsPerPixel
        0x0000,          # flags: uncompressed
    )
    length_field = struct.pack("<H", bmp_len & 0xFFFF)
    return header + length_field + bitmap
