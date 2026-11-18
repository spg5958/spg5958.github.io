#!/usr/bin/env python3
"""Serialize deterministic offline ClientHello framing fixtures; never transmit."""
import hashlib
import json
from pathlib import Path
import struct


def u16(n):
    return struct.pack("!H",n)


def extension(kind,body):
    return u16(kind)+u16(len(body))+body


def client_hello(hostname):
    host=hostname.encode("ascii")
    name=b"\x00"+u16(len(host))+host
    extensions=(extension(0,u16(len(name))+name)
        +extension(10,u16(2)+u16(23))
        +extension(11,b"\x01\x00")
        +extension(13,u16(4)+b"\x04\x01\x04\x03"))
    body=(b"\x03\x03"+bytes(range(32))+b"\x00"+u16(2)+b"\xc0\x2f"
          +b"\x01\x00"+u16(len(extensions))+extensions)
    handshake=b"\x01"+len(body).to_bytes(3,"big")+body
    return b"\x16\x03\x03"+u16(len(handshake))+handshake


def build(output=None):
    out=Path(output) if output else Path(__file__).with_name("fixtures")
    out.mkdir(parents=True,exist_ok=True)
    rows={}
    for label,hostname in (("benign","allowed.example"),("blocked","blocked.example")):
        data=client_hello(hostname)
        (out/f"clienthello_{label}.bin").write_bytes(data)
        rows[label]={"hostname":hostname,"length_bytes":len(data),"hex":data.hex(),
                     "sha256":hashlib.sha256(data).hexdigest()}
    assert rows["benign"]["length_bytes"]==rows["blocked"]["length_bytes"]<32768
    meta={"purpose":"offline TLS1.2 ClientHello framing fixture, one TCP segment; no transmission code",
          "hostnames":"Equal-length placeholders. Neither name has measured censorship status. Replace with calibrated equal-length names before empirical use.",
          "tls":"TLS1.2 ClientHello; ECDHE_RSA_AES_128_GCM_SHA256; secp256r1; null compression; SNI and signature algorithms",
          "fixed_random":"00..1f for reproducible offline serialization only",
          "length_symbol":"L_readout","segmentation":"one segment","variants":rows,
          "limitations":"Framing only; TLS negotiation and server application replies are not simulated."}
    (out/"clienthello.json").write_text(json.dumps(meta,indent=2))
    return meta


if __name__=="__main__":
    print(json.dumps({k:v["length_bytes"] for k,v in build()["variants"].items()}))
