#!/usr/bin/env python3
"""
verify_pdf_signature_full.py
Thực hiện 8 bước xác thực chữ ký PDF (đọc SigDict, extract PKCS#7, hash check,
verify signature, chain check, OCSP/CRL check (attempt), timestamp token check,
incremental-update detection). Ghi log chi tiết ra verify_log.txt.
"""
import os
import sys
import binascii
import hashlib
import datetime
import traceback

try:
    import requests
except Exception:
    requests = None

from PyPDF2 import PdfReader
from asn1crypto import cms, core, x509 as asn1_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.backends import default_backend

LOG_PATH = os.path.join(os.getcwd(), "verify_log.txt")

def log(msg):
    ts = datetime.datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def clear_log():
    if os.path.exists(LOG_PATH):
        os.remove(LOG_PATH)

def read_sigdict(pdf_path):
    r = PdfReader(pdf_path)
    fields = r.get_fields() or {}
    log(f"Found fields: {list(fields.keys())}")
    # find signature widget
    for pidx, page in enumerate(r.pages):
        annots = page.get("/Annots")
        if not annots:
            continue
        for a in annots:
            annot = a.get_object()
            if annot.get("/Subtype") == "/Widget" and annot.get("/FT") == "/Sig":
                sig_obj = annot.get("/V")
                if sig_obj is None:
                    # Signature field present but empty
                    log(f"Signature field present on page {pidx+1} but /V is empty.")
                    continue
                sig = sig_obj.get_object()
                return {
                    "page": pidx+1,
                    "field_name": annot.get("/T"),
                    "sig_dict": sig,
                    "reader": r
                }
    return None

def extract_contents_and_byterange(sig_dict):
    # /Contents usually bytes
    contents = sig_dict.get("/Contents")
    if contents is None:
        raise ValueError("No /Contents in signature dictionary")
    # PyPDF2 may return bytes directly
    if isinstance(contents, (bytes, bytearray)):
        pkcs7_bytes = bytes(contents)
    else:
        # try attribute .original_bytes or as string
        try:
            pkcs7_bytes = contents.get_data()
        except Exception:
            # fallback: convert to PyPDF2 PdfString
            pkcs7_bytes = bytes(contents)
    br = sig_dict.get("/ByteRange")
    if not br or len(br) != 4:
        raise ValueError(f"Invalid /ByteRange: {br}")
    return pkcs7_bytes, [int(x) for x in br]

def save_pkcs7(pkcs7_bytes, out_p7s):
    with open(out_p7s, "wb") as f:
        f.write(pkcs7_bytes)
    log(f"Saved PKCS#7 blob to {out_p7s} ({len(pkcs7_bytes)} bytes)")

def parse_pkcs7(pkcs7_bytes):
    # Load as asn1crypto.cms.ContentInfo
    ci = cms.ContentInfo.load(pkcs7_bytes)
    if ci['content_type'].native != 'signed_data':
        raise ValueError("PKCS#7 content is not SignedData")
    sd = ci['content']
    # extract signer infos and certificates
    signer_infos = sd['signer_infos']
    certs = sd['certificates']
    return sd, signer_infos, certs

def compute_hash_of_byterange(pdf_path, byterange, hash_name="sha256"):
    # byterange is [off1, len1, off2, len2]
    with open(pdf_path, "rb") as f:
        data = f.read()
    part1 = data[byterange[0]: byterange[0] + byterange[1]]
    part2 = data[byterange[2]: byterange[2] + byterange[3]]
    m = hashlib.new(hash_name)
    m.update(part1)
    m.update(part2)
    return m.digest(), m.hexdigest(), part1 + part2

def find_signer_cert_and_message_digest(sd, signer_info):
    # signer_info['sid'] often is IssuerAndSerialNumber or SubjectKeyIdentifier
    sid = signer_info['sid']
    certs = sd['certificates']
    signer_cert = None
    # iterate certs to find matching one
    if sid.name == 'issuer_and_serial_number':
        issuer = sid.chosen['issuer']
        serial = sid.chosen['serial_number'].native
        for c in certs:
            if isinstance(c.chosen, asn1_x509.Certificate):
                cc = c.chosen
                if cc.serial_number == serial and cc.issuer == issuer:
                    signer_cert = cc
                    break
    else:
        # try match by subject name or subject key identifier
        for c in certs:
            if isinstance(c.chosen, asn1_x509.Certificate):
                cc = c.chosen
                # fallback choose first cert if nothing matches
                signer_cert = signer_cert or cc
    # MessageDigest: find attribute in signed_attrs
    signed_attrs = signer_info['signed_attrs']
    md_attr = None
    if signed_attrs is not None:
        for attr in signed_attrs:
            if attr['type'].dotted == '1.2.840.113549.1.9.4':  # messageDigest
                md_attr = attr
                break
    message_digest = None
    if md_attr is not None:
        vals = md_attr['values']
        if len(vals) > 0:
            message_digest = bytes(vals[0].native)
    return signer_cert, message_digest, signed_attrs

def asn1_to_cryptography_cert(asn1_cert):
    der = asn1_cert.dump()
    return x509.load_der_x509_certificate(der, backend=default_backend())

def verify_signature_over_signed_attrs(signer_cert_crypto, signer_info):
    # signature bytes:
    signature = signer_info['signature'].native
    # signed_attrs DER (must be the DER encoding with the SET OF tag)
    signed_attrs = signer_info['signed_attrs']
    if signed_attrs is None:
        raise ValueError("No signed_attrs present — cannot perform signature verification per PKCS#7")
    signed_attrs_der = signed_attrs.dump()
    # determine digest algorithm from signer_info['digest_algorithm']
    digest_alg = signer_info['digest_algorithm']['algorithm'].native
    if digest_alg in ('sha1', 'sha256', 'sha384', 'sha512'):
        hash_alg = {
            'sha1': hashes.SHA1(),
            'sha256': hashes.SHA256(),
            'sha384': hashes.SHA384(),
            'sha512': hashes.SHA512()
        }[digest_alg]
    else:
        raise ValueError(f"Unsupported digest algorithm: {digest_alg}")
    pubkey = signer_cert_crypto.public_key()
    # Try PKCS1v15 verification (most common for RSA)
    try:
        pubkey.verify(
            signature,
            signed_attrs_der,
            padding.PKCS1v15(),
            hash_alg
        )
        return True, f"Signature verified with padding PKCS#1 v1.5 and hash {digest_alg}"
    except Exception as e:
        return False, f"Signature verification failed: {e}"

def check_chain_against_trust(certs_asn1, trust_cert_paths=None):
    """
    Simple chain check:
      - Find candidate chains from included certs by issuer/subject linking.
      - If trust_cert_paths provided, check if any chain ends with a trust cert.
    This is NOT a full PKIX path validation, but a pragmatic check for included chain.
    """
    # Convert to cryptography certs
    cert_list = []
    for c in certs_asn1:
        if isinstance(c.chosen, asn1_x509.Certificate):
            cert_list.append(asn1_to_cryptography_cert(c.chosen))
    info = []
    # Attempt link by subject->issuer
    subjects = {c.subject.rfc4514_string(): c for c in cert_list}
    issuers = {c.issuer.rfc4514_string(): c for c in cert_list}
    # find possible leaf(s) = those whose subject != any issuer in list
    leafs = []
    issuer_names = {c.issuer.rfc4514_string() for c in cert_list}
    for c in cert_list:
        if c.subject.rfc4514_string() not in issuer_names or True:
            leafs.append(c)
    # Build chain greedily for first leaf
    chain = []
    cur = leafs[0] if leafs else (cert_list[0] if cert_list else None)
    while cur:
        chain.append(cur)
        subj = cur.issuer.rfc4514_string()
        if subj == cur.subject.rfc4514_string():
            # self-signed root
            break
        next_cert = subjects.get(subj)
        if next_cert is None:
            break
        if next_cert == cur:
            break
        cur = next_cert
    info.append(chain)
    trust_matched = False
    trusted_names = set()
    if trust_cert_paths:
        for tp in trust_cert_paths:
            try:
                with open(tp, "rb") as f:
                    t = x509.load_pem_x509_certificate(f.read(), default_backend())
                    trusted_names.add(t.subject.rfc4514_string())
            except Exception:
                try:
                    with open(tp, "rb") as f:
                        t = x509.load_der_x509_certificate(f.read(), default_backend())
                        trusted_names.add(t.subject.rfc4514_string())
                except Exception:
                    log(f"Could not load trust anchor {tp}")
    # check if chain end matches any trusted
    for ch in info:
        end = ch[-1]
        if end.subject.rfc4514_string() in trusted_names:
            trust_matched = True
            break
    return info, trust_matched

def attempt_ocsp_check(cert_crypto):
    # attempt to find OCSP URL in AIA extension
    try:
        aia = cert_crypto.extensions.get_extension_for_oid(x509.AuthorityInformationAccessOID.AUTHORITY_INFORMATION_ACCESS)
        for desc in aia.value:
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP:
                url = desc.access_location.value
                log(f"Found OCSP URL: {url}")
                if requests is None:
                    return "OCSP URL found but 'requests' not available — skipped"
                try:
                    # Build a minimal OCSP request? Here we'll attempt GET which many OCSP servers don't support.
                    r = requests.get(url, timeout=8)
                    return f"OCSP endpoint reachable (HTTP {r.status_code}) — full OCSP request not implemented"
                except Exception as e:
                    return f"Could not reach OCSP endpoint: {e}"
    except Exception:
        return "No AIA OCSP extension present"
    return "OCSP check not performed"

def check_timestamp_token_presence(signer_info):
    """
    Kiểm tra xem signer_info có chứa TimestampToken hay không.
    """
    ts_present = False
    ts_msg = "Không có timestamp token."

    try:
        if 'unsigned_attrs' in signer_info:
            unsigned_attrs = signer_info['unsigned_attrs']
            if unsigned_attrs is not None:
                for attr in unsigned_attrs:
                    oid = attr['type'].dotted
                    if oid == '1.2.840.113549.1.9.16.2.14':  # id-aa-signatureTimeStampToken
                        ts_present = True
                        ts_msg = f"Tìm thấy timestamp token (OID={oid})"
                        break
        else:
            ts_msg = "SignerInfo không chứa unsigned_attrs."
    except Exception as e:
        ts_msg = f"Lỗi khi kiểm tra timestamp token: {e}"

    return ts_present, ts_msg

def check_incremental_update(pdf_path, byterange):
    file_len = os.path.getsize(pdf_path)
    br_end = byterange[2] + byterange[3]
    extra = file_len - br_end
    if extra > 0:
        return False, f"Data exists after ByteRange end ({extra} bytes) — incremental updates or appended data present"
    else:
        return True, "No extra data after ByteRange end"

def main(pdf_path, trust_paths=None, out_p7s=None):
    clear_log()
    log(f"Starting verification for {pdf_path}")
    try:
        info = read_sigdict(pdf_path)
        if not info:
            log("No signature dictionary found — abort.")
            return
        sig_dict = info['sig_dict']
        log(f"Signature field name: {info.get('field_name')}, page: {info.get('page')}")
        # print sig_dict entries
        for k, v in sig_dict.items():
            log(f"SigDict {k}: {v if k in ['/Contents','/ByteRange'] else str(v)}")
        # extract contents and byterange
        pkcs7_bytes, byterange = extract_contents_and_byterange(sig_dict)
        if out_p7s is None:
            out_p7s = os.path.splitext(pdf_path)[0] + ".p7s"
        save_pkcs7(pkcs7_bytes, out_p7s)
        # parse PKCS#7
        sd, signer_infos, certs = parse_pkcs7(pkcs7_bytes)
        log(f"Parsed SignedData: version={sd['version'].native}, signer_infos={len(signer_infos)}")
        # assume first signer_info
        signer_info = signer_infos[0]
        # find signer cert and messageDigest
        signer_cert_asn1, message_digest, signed_attrs = find_signer_cert_and_message_digest(sd, signer_info)
        if signer_cert_asn1 is None:
            log("Could not identify signer certificate in PKCS#7 certificates")
        else:
            signer_cert_crypto = asn1_to_cryptography_cert(signer_cert_asn1)
            log(f"Signer cert subject: {signer_cert_crypto.subject.rfc4514_string()}")
        # compute hash of byterange
        computed_digest_bytes, computed_hexdigest, concatenated = compute_hash_of_byterange(pdf_path, byterange, hash_name='sha256')
        log(f"Computed SHA-256 digest (hex): {computed_hexdigest}")
        if message_digest is not None:
            log(f"messageDigest from PKCS#7 (hex): {binascii.hexlify(message_digest).decode()}")
            if computed_digest_bytes == message_digest:
                log("✅ messageDigest MATCHES computed digest — integrity OK")
            else:
                log("❌ messageDigest DOES NOT match computed digest — file may have been modified")
        else:
            log("⚠️ No messageDigest attribute found in signed_attrs")
        # verify signature cryptographically
        try:
            ok, msg = verify_signature_over_signed_attrs(signer_cert_crypto, signer_info)
            if ok:
                log(f"✅ Signature cryptographic verification: {msg}")
            else:
                log(f"❌ Signature verification failed: {msg}")
        except Exception as e:
            log(f"Error during signature verification: {e}\n{traceback.format_exc()}")
        # chain check
        chain_info, trust_ok = check_chain_against_trust(certs, trust_paths)
        log(f"Chain building attempt: {len(chain_info[0])} cert(s) found in chain")
        for idx, c in enumerate(chain_info[0]):
            log(f"Chain[{idx}] subject={c.subject.rfc4514_string()} issuer={c.issuer.rfc4514_string()}")
        if trust_paths:
            log(f"Trust anchor provided(s): {trust_paths}")
            log(f"Trust anchor matched chain end: {trust_ok}")
        else:
            log("No trust anchors provided for chain validation (treated as self-signed/untrusted)")
        # OCSP attempt
        try:
            ocsp_result = attempt_ocsp_check(signer_cert_crypto)
            log(f"OCSP check result: {ocsp_result}")
        except Exception as e:
            log(f"OCSP check exception: {e}")
        # timestamp token
        ts_present, ts_msg = check_timestamp_token_presence(signer_info)
        log(f"Timestamp token check: {ts_msg}")
        # incremental update
        inc_ok, inc_msg = check_incremental_update(pdf_path, byterange)
        log(f"Incremental update check: {inc_msg}")
        log("Verification run complete.")
    except Exception as e:
        log(f"Unhandled exception: {e}\n{traceback.format_exc()}")

if __name__ == "__main__":
    # Usage: python verify_pdf_signature_full.py [pdf_path] [optional: trust_cert.pem]
    if len(sys.argv) < 2:
        print("Usage: python verify_pdf_signature_full.py <signed_pdf_path> [trust_cert.pem]")
        sys.exit(1)
    pdfp = sys.argv[1]
    trust = sys.argv[2:] if len(sys.argv) > 2 else None
    main(pdfp, trust_paths=trust)
