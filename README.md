# PoC-RemoteAttestation

EK Profile 
https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf

### 2.2.1.4 Low Range

```
The Low Range is at NV Indices 0x01c00002 - 0x01c0000c.
0x01c00002 RSA 2048 EK Certificate
0x01c00003 RSA 2048 EK Nonce
0x01c00004 RSA 2048 EK Template
0x01c0000a ECC NIST P256 EK Certificate
0x01c0000b ECC NIST P256 EK Nonce
0x01c0000c ECC NIST P256 EK Template
EK Certificate NV Index(es) SHOULD be Populated by the manufacturer.
The manufacturer SHOULD leave the EK Nonce NV Index Absent. If a unique field is specified, it
SHOULD be included as part of the associated EK Template NV Index.
```

### 2.2.1.9 Read EK certificates and create the associated EKs

```
2. Identify whether the returned NV index handles lie in the Low Range (0x01C00002 -
0x01C0000C) or in the High Range (0x01C00012 - 0x01C07FFF).
  a. In the Low Range, an EK Certificate, an EK Nonce (recommended to be Absent),
  and an EK Template (recommended to be Absent) are Populated at assigned
  standard handle values. If present,
    i. an EK Certificate is at 0x01c00002 (RSA) or 0x01c0000a (ECC)
    ii. an EK Nonce is at 0x01c00003 (RSA) or 0x01c0000b (ECC)
    iii. an EK Template is at 0x01c00004 (RSA) or 0x01c0000c (ECC)
  b. In the High Range, no standard handle values are assigned. An EK Certificate is
  Populated at an even handle value, and (if present) an EK Template is Populated
  at the subsequent odd handle value.
```
