---
title: "Post-Quantum EDHOC - Initiator and Responder using signature and/or KEM"
abbrev: "PQ-EDHOC - Sign and KEM"
category: info

docname: draft-papon-pq-edhoc-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
#number:
date: 2026-02-26
consensus: false
v: 3
keyword:
  - EDHOC
  - Post-Quantum
  - Authentication Key Exchange

author:
  - fullname: Clément Papon
    organization: XLIM UMR CNRS 7252 - Limoges University
    email: clement.papon@unilim.fr
  - fullname: Cristina Onete
    organization: XLIM UMR CNRS 7252 - Limoges University
    email: maria-cristina.onete@unilim.fr

normative:
    I-D.spm-lake-pqsuites: I-D.spm-lake-pqsuites
    I-D.pocero-authkem-edhoc: I-D.pocero-authkem-edhoc
    I-D.pocero-authkem-ikr-edhoc: I-D.pocero-authkem-ikr-edhoc
    RFC5116: RFC5116
    RFC8392: RFC8392
    RFC8742: RFC8742
    RFC8949: RFC8949
    RFC9052: RFC9052
    RFC9360: RFC9360
    RFC9528: RFC9528

informative:
    RFC9053: RFC9053
    RFC9794: RFC9794

--- abstract

This document specifies two extensions to the Ephemeral Diffie-Hellman over COSE (EDHOC). These two protocol versions aim to provide quantum-resistance to the original EDHOC protocol, while reducing message-complexity with respect to parallel drafts. The document defines: (1) a 3-message quantum-resistant EDHOC proposal when the Initiator knows the Responder; in this version, the Initiator authenticates using a signature, while the Responder uses a KEM; (2) a 3-or-4-message quantum-resistant EDHOC proposal, which proposes a tradeoff between message-complexity and computational overhead.

--- middle

# Introduction

This document aims to present new alternatives for rendering the Ephemeral Diffie-Hellman Over COSE (EDHOC) protocol quantum-resistant. The main goal is to reduce the number of messages exchanged during the handshake, using a combination of KEMs and signatures, as well as Post-Quantum Cryptography (PQC) cipher suites, for secure key-exchange and authentication.

In this draft we:
  - propose, build on {{I-D.pocero-authkem-ikr-edhoc}}, a version of quantum-resistant EDHOC where the Initiator knows the Responder, but in a scenario where the Initiator authenticates with a signature (ML-DSA) and the Responder with a KEM (ML-KEM).

  - propose, building on {{I-D.pocero-authkem-edhoc}}, a version of the protocol that requires, depending on the case, either only 3 or 4 mandatory messages. This second version reduces the message overhead, but comes at an additional computational overhead for (at least) one of the two parties.

The two proposals in this draft can be viewed to extend (in the case of the first bullet-point) and respectively to provide an alternative (in the case of the second bullet-point) to the current proposal for quantum-resistant EDHOC.

## Terminology and Requirements Language
{::boilerplate bcp14-tagged}


Readers are expected to be familiar with the terms and concepts described in EDHOC {{RFC9528}}, CBOR {{RFC8949}}, CBOR Sequences {{RFC8742}}, COSE Structures and Processing {{RFC9052}} and COSE Algorithms {{RFC9053}}.

## Definitions

### KEMs (Key Encapsulation Mechanisms)
TODO

### Digital Signature
TODO

# Post-Quantum EDHOC when the Initiator knows the Responder (PQ-EDHOC-IKR)

## Motivation

In {{I-D.pocero-authkem-ikr-edhoc}}, the authors adopt an EDHOC approach for use cases where the Initiator already knows the identity of the Responder, in a post-quantum version using ephemeral and static KEMs for authentication. The Initiator, knowing the long-term public key of the Responder, can derive the shared-secret (ss_R) and compute a key, then encrypt part of the first message. It can thus send its identity directly and securely authenticate itself, since only the Responder with its long-term secret key can decrypt the first message. Knowing the Initiator's identity, the Responder can derive the second shared-secret (ss_I) and continue the key derivation schedule. Sending the encrypted second message allows it to securely confirm its identity to the Initiator.

The key motivation behind our current proposal is a desire to reduce the message-complexity of quantum-resistant EDHOC. We propose an extension to draft proposal {{I-D.pocero-authkem-ikr-edhoc}}, which allows the Initiator and Responder to authenticate using different mechanisms -- much as in the original EDHOC. In particular, while the Responder still authenticates using a KEM, in our proposal the Initiator will use a signature.

This approach comes with the following benefit: there is no need to partially encrypt the first message. Instead, during the third message, the Initiator calculates a MAC and signs it. Upon receiving the encrypted third message, the Responder, after decryption, authenticates the Initiator in the usual EDHOC manner.


## PQ-EDHOC-IKR protocol overview

### PQ-EDHOC-IKR protocol description

We present here a high-level description of our PQ-EDHOC-IKR where the Initiator authenticates with a signature and the Responder with a KEM.

~~~~~~~~~~
  I                                                         R
 ---                                                       ---
  |   METHOD, SUITES_I, kem.pk_eph, kem.ct_R, C_I, EAD_1    |
  +--------------------------------------------------------->
  |                        message_1                        |
  |                                                         |
  |  kem.ct_eph, Enc(KEYSTREAM_2, ID_CRED_R, MAC_2, EAD_2)  |
  <---------------------------------------------------------+
  |                        message_2                        |
  |                                                         |
  |           AEAD(ID_CRED_I, Signature_3, EAD_3)           |
  +--------------------------------------------------------->
  |                        message_3                        |
  |                                                         |
  |                       AEAD(EAD_4)                       |
  <- - - - - - - - - - - - - - - - - - - - - - - - - - - - -+
  |                        message_4                        |
~~~~~~~~~~

Figure 1: PK-EDHOC-IKR (I sign, R kem) message flow


#### Formatting and sending message_1

As in the usual EDHOC protocol, the first message (message_1) consists of:

  - `METHOD` -> as specified in {{RFC9528}} it is an integer specifying the authentication method the Initiator wants to use.
  - `SUITES_I` -> it consists of an ordered set of algorithms supported by the Initiator and formatted as specified in {{RFC9528}}.
  - `C_I` (and also as `C_R`, which will appears later) -> the Connection Identifiers chosen by the Initiator (C_I) and by the Responder (`C_R`) as specified in {{RFC9528}}.
  - `EAD_1` (and also `EAD_2`, `EAD_3` and `EAD_4`, which will appear later) -> External Authorization Data, respectively included in `message_1`, `message_2`, `message_3` (and optionally) `message_4`, and formatted as specified in {{RFC9528}}.
  - `kem.pk_eph` -> the Ephemeral KEM public key generated by the Initiator.
  - `kem.ct_R` -> based on the Responder long-term KEM public key, the Initiator computes `ss_R` and `kem.ct_R` with the KEM.Encapsulation algorithm. He keeps secret `ss_R` to compute, later, `PRK_3e2m`, and sends `kem.ct_R` to the Responder.


#### Processing message_1, formatting and sending message_2

On the reception of the first message, the Responder first recovers ss_R thanks to his long-term KEM secret key kem.sk_R and kem.ct_R, using the KEM.Decapsulation algorithm (if the decapsulation process fails, he aborts). He then proceeds as in the original EDHOC protocol with elements METHOD, SUITES_I, C_I and EAD_1. Finally, using kem.pk_eph and the KEM.Encapsulation algorithm, he computes the ephemeral ciphertext kem.ct_eph and the ephemeral shared-secret ss_eph.

The Responder select its Connection Identifier C_R as specified in {{RFC9528}}. He then computes:

  - TH_2 = H(kem.ct_eph, H(message_1)).

  - PRK_2e = EDHOC_Extract(TH_2, ss_eph) -> the salt SHALL be TH_2 and the IKM SHALL be the ephemeral shared-secret ss_eph.

And also, as in {{RFC9528}}:

  - KEYSTREAM_2 = EDHOC_KDF(PRK_2e,0,TH_2,plaintext_length)
  - SALT_3e2m = EDHOC_KDF(PRK_2e,1,TH_2,hash_length)


Compared to {{RFC9528}}, the computation of PRK_3e2m is modified as follows :

  - PRK_3e2m = EDHOC_Extract(SALT_3e2m, ss_R).

The Responder now computes MAC_2 and assembles PLAINTEXT_2:

  - MAC_2 = EDHOC_KDF(PRK_3e2m, 2, C_R, ID_CRED_R, TH_2, EAD_2, mac_length_2).
  - PLAINTEXT_2 = (C_R, ID_CRED_R, MAC_2, EAD_2).

So the second message consists of:
  - kem.ct_eph -> the ephemeral ciphertext obtained with kem.pk_eph.
  - CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2.


#### Processing message_2, formatting and sending message_3.


# Second protocol
Our second idea is to propose a tradeoff, allowing for a reduced number of messages in the quantum-resistant EDHOC handshake, which come at a slightly higher computational overhead.

# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


# Acknowledgments
TODO acknowledge.

--- back

