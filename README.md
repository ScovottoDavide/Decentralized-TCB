# PoC-RemoteAttestation

EK Profile 
https://trustedcomputinggroup.org/wp-content/uploads/TCG_IWG_EKCredentialProfile_v2p4_r3.pdf

### 2.2.1.4 Low Range

`
The Low Range is at NV Indices 0x01c00002 - 0x01c0000c.
0x01c00002 RSA 2048 EK Certificate
0x01c00003 RSA 2048 EK Nonce
0x01c00004 RSA 2048 EK Template
0x01c0000a ECC NIST P256 EK Certificate
0x01c0000b ECC NIST P256 EK Nonce
0x01c0000c ECC NIST P256 EK Template
EK Certificate NV Index(es) SHOULD be Populated by the manufacturer.
The manufacturer SHOULD leave the EK Nonce NV Index Absent. If a unique field is specified, it
SHOULD be included as part of the associated EK Template NV Index. `

