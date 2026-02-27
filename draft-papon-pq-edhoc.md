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

In {{I-D.pocero-authkem-ikr-edhoc}}, the authors adopt an EDHOC approach for use cases where the Initiator already knows the identity of the Responder, in a post-quantum version using ephemeral and static KEMs for authentication. The Initiator, knowing the long-term public key of the Responder, can derive the shared-secret (ss_R) and compute a key, then encrypt part of the first message. It can thus send its identity directly and securely authenticate himself, since only the Responder with its long-term secret key can decrypt the first message. Knowing the Initiator's identity, the Responder can derive the second shared-secret (ss_I) and continue the key derivation schedule. Sending the encrypted second message allows it to securely confirm its identity to the Initiator.

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

Figure 1: PQ-EDHOC-IKR (I sign, R kem) message flow.


#### Formatting and sending `message_1`

As in the usual EDHOC protocol, the first message (`message_1`) consists of:

  - `METHOD` --> as specified in {{RFC9528}} it is an integer specifying the authentication method the Initiator wants to use;
  - `SUITES_I` --> it consists of an ordered set of algorithms supported by the Initiator and formatted as specified in {{RFC9528}};
  - `C_I` (and also as `C_R`, which will appears later) --> the Connection Identifiers chosen by the Initiator (C_I) and by the Responder (`C_R`) as specified in {{RFC9528}};
  - `EAD_1` (and also `EAD_2`, `EAD_3` and `EAD_4`, which will appear later) -> External Authorization Data, respectively included in `message_1`, `message_2`, `message_3` (and optionally) `message_4`, and formatted as specified in {{RFC9528}};
  - `kem.pk_eph` --> the Ephemeral KEM public key generated by the Initiator;
  - `kem.ct_R` --> based on the Responder long-term KEM public key, the Initiator computes `ss_R` and `kem.ct_R` with the KEM.Encapsulation algorithm. He keeps secret `ss_R` to compute, later, `PRK_3e2m`, and sends `kem.ct_R` to the Responder.


#### Processing `message_1`, formatting and sending `message_2`

On the reception of the first message, the Responder first recovers `ss_R` thanks to his long-term KEM secret key `kem.sk_R` and `kem.ct_R`, using the `KEM.Decapsulation` algorithm (if the decapsulation process fails, he aborts). He then proceeds as in the original EDHOC protocol with elements `METHOD`, `SUITES_I`, `C_I` and `EAD_1`. Finally, using `kem.pk_eph` and the `KEM.Encapsulation` algorithm, he computes the ephemeral ciphertext `kem.ct_eph` and the ephemeral shared-secret `ss_eph`.

The Responder select its Connection Identifier `C_R` as specified in {{RFC9528}}. He then computes:

  - `TH_2 = H(kem.ct_eph, H(message_1))`;

  - `PRK_2e = EDHOC_Extract(TH_2, ss_eph)` --> the salt SHALL be `TH_2` and the IKM SHALL be the ephemeral shared-secret `ss_eph`.

And also, as in {{RFC9528}}:

  - `KEYSTREAM_2 = EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)`;
  - `SALT_3e2m = EDHOC_KDF(PRK_2e, 1, TH_2, hash_length)`.


Compared to {{RFC9528}}, the computation of `PRK_3e2m` is modified as follows :

  - `PRK_3e2m = EDHOC_Extract(SALT_3e2m, ss_R)`.

The Responder now computes `MAC_2` and assembles `PLAINTEXT_2`:

  - `MAC_2 = EDHOC_KDF(PRK_3e2m, 2, C_R, ID_CRED_R, TH_2, EAD_2, mac_length_2)`;
  - `PLAINTEXT_2 = (C_R, ID_CRED_R, MAC_2, EAD_2)`.

So the second message consists of:

  - `kem.ct_eph` --> the ephemeral ciphertext obtained with `kem.pk_eph`;
  - `CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2`.


#### Processing `message_2`, formatting and sending `message_3`.

On reception of the second message, the Initiator, using `kemp.ct_eph`, can compute the ephemeral shared-secret `ss_eph`. As the Responder did, he computes `TH_2`, `PRK_2e` and `KEYSTREAM_2`. He can now decipher and retrieve : `PLAINTEXT_2 = CIPHERTEXT_2 XOR KEYSTREAM_2`.

Thanks to `ID_CRED_R`, the Initiator verifies the validity of the long-term KEM public key of the Responder, `kemp.pk_R`, and computes `SALT_3e2m`and `PRK_3e2m`, using the shared-secret `ss_R`he generates at the beginning of the exchange.

At this point the Initiator is abable to authenticate the Responder (at least, make sure he is talking to the endpoint he hopes to talk to). For that, he computes, as the Responder did, the MAC `MAC_2`. If it machtes with the one he received, then he properly authenticated the Responder. Otherwise he aborts.

It is now up to the Initiator to authenticate himself. To do so, the Initiator computes the following elements:

  - `TH_3 = H(TH_2, PLAINTEXT_2, ID_CRED_R)`;
  - `K_3 = EDHOC_KDF(PRK_3e2m, 3, TH_3, key_length)`;
  - `IV_3 = EDHOC_KDF(PRK_3e2m, 4, TH_3, iv_length)`;
  - `MAC_3 = EDHOC_KDF(PRK_3e2m, 6, ID_CRED_I, TH_3, EAD_3, mac_length_3)`.

In this version of the protocol, the Initiator authenticates itself to the Responder with a signature:

  - `SIGNATURE_3 = DS.Sign(sign.sk_I, (ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length))`

where `sign.sk_I` is the long-term signing private key of the Initiator.

Setting `PLAINTEXT_3 = (ID_CRED_I, SIGNATURE_3, EAD_3)`, the Initiator ciphers `PLAINTEXT_3` with the AEAD encryption algorithm negociated in `SUITES_I`.


#### Processing `message_3`

On reception of `message_3`, the Responder computes `TH_3`, `K_3`, and `IV_3` as the Initiator did, and deciphers `CIPHERTEXT_3` with the AEAD decryption algorithm. With `PLAINTEXT_3`, he can compute `MAC_3`on his side, and verify the signature:

  - `DS.Verify(sign.pk_I, (ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length))`

where `sign.pk_I` is the long-term signing public key of the Initiator. If the verification algorithm returns 1, the Responder properly authenticated the Initiator. Otherwise he aborts.


#### Optionally formatting, sending and recieving `message_4`

If the Responder decides of a fourth mandatory message, he then computes the following elements:

  - `TH_4 = H(TH_3, PLAINTEXT_3, ID_CRED_I)`;
  - `K_4 = EDHOC_KDF(PRK_4e3m, 8, TH_4, key_length)`;
  - `IV_4 = EDHOC_KDF(PRK_4e3m, 9, TH_4, iv_length)`.

Using the AEAD encryption algorithm, he ciphers `PLAINTEXT_4 = EAD_4`and sends it to the Initiator. The later computes `TH_4`, `K_4`, `IV_4`, and deciphers `CIPHERTEXT_4` thanks to the AEAD decryption algorithm.



#### Computing the session key `PRK_out`

It doesn't matter if there is a fourth mandatory message, in any case, both the Initiator and the Responder, in order to compute the key `PRK_out`, have to calcule the fourth transcript hash:

  - `TH_4 = H(TH_3, PLAINTEXT_3, ID_CRED_I)`.

With that element, using the EDHOC_KDF, they both obtain:

  - `PRK_out = EDHOC_KDF(PRK_3e2m, 7, TH_4, hash_length)`

which is the desired session key, and the authentication process is fully achieved.


### Key Derivation Schedule

In this section we summarize the key derivation operations that appears throughout the protocol.

~~~~~~~~~~~
          +--------------------------------+
          |TH_2=H(kem.ct_eph, H(message_1))|
          +-------+------------------------+              PLAINTEXT_1
                 |                                               |
  +------+   +---+---+   +------+   +------+   +-----------+   +-+-+
  |ss_eph|-->|Extract|-->|PRK_2e|-->|Expand|-->|KEYSTREAM_2|-->|XOR|
  +------+   +-------+   +---+--+   +---+--+   +-----------+   +-+-+
                             |          |                        |
                             |          |                        v
                             |        +-+--+           +---------+--+
                             |        |TH_2|           |CIPHERTEXT_2|
                             |        +--+-+           +------------+
                         +---+--+        |
                         |Expand|--------+
                         +---+--+
                            |
                            |
                      +-----+---+
               +------|SALT_3e2m|
               |      +---------+
               |
  +----+   +---+---+   +--------+   +------+   +-----+
  |ss_R|-->|Extract|-->|PRK_3e2m|-->|Expand|-->|MAC_2|
  +----+   +-------+   +---+----+   +------+   +-----+
                           |                              PLAINTEXT_3
                           |                                   |
                           |        +------+   +--------+   +--+-+
                           +--------|Expand|-->|K_3/IV_3|-->|AEAD|
                           |        +---+--+   +--------+   +--+-+
                           |            |                      |
                           |            |                      v
                           |            |              +-------+----+
                           |            |              |CIPHERTEXT_3|
                           |            |              +------------+
                           |            |
                           |   +--------+---------------------------+
                           |   |TH_3=H(TH_2, PLAINTEXT_2, ID_CRED_R)|
                           |   +------------------------------------+
                           |
                           |       +------+   +-----+   +-----------+
                           +-------|Expand|-->|MAC_3|-->|SIGNATURE_3|
                           |       +------+   +-----+   +-----------+
                           |
                           |                              PLAINTEXT_4
                           |                                   |
                           |        +------+   +--------+   +--+-+
               message_4?  +--------|Expand|-->|K_4/IV_4|-->|AEAD|
                           |        +---+--+   +--------+   +--+-+
                           |            |                      |
                           |            |                      v
                           |            |              +-------+----+
                           |            |              |CIPHERTEXT_4|
                           |            |              +------------+
                           |            |
                           |   +--------+---------------------------+
                           |   |TH_4=H(TH_3, PLAINTEXT_3, ID_CRED_I)|
                           |   +--------+---------------------------+
                           |            |
                           |            |
                           |        +---+--+   +-------+
                           +--------|Expand|-->|PRK_out|
                                    +------+   +-------+
~~~~~~~~~~
Figure 2: PQ-EDHOC-IKR (I sign, R kem) key derivation schedule.

### Additional explainations
TODO some other explainations.

## Analysis

TODO efficiency and optimization analysis.

# KEM & Sign Authentication for Post-Quantum EDHOC

## Motivation

Our second idea is to propose a tradeoff, allowing for a reduced number of messages in the quantum-resistant EDHOC handshake, which come at a slightly higher computational overhead compared to {{I-D.pocero-authkem-edhoc}}.

Starting from the standard EDHOC protocol, method 0 allows for mutual authentication via signature between both users. As proposed in {{I-D.pocero-authkem-edhoc}}, replacing classical signatures with post-quantum resistant signatures such as ML-DSA and ephemeral Diffie-Hellman elements with a KEM like ML-KEM seems reasonable to make EDHOC post-quantum resistant (even if this still need to be proved).
These two changes do not affect the number of mandatory messages, since the fundamental structure of the protocol is preserved (however a post-quantum signature will likely be more computationally expensive, just like a KEM).
Things get complicated when trying to apply these modifications to the other three methods. Continuing on this track, we replace ephemeral Diffie-Hellman elements with an ephemeral KEM. This does not affect the usual structure of EDHOC. However, if we want to take it further and also replace long-term Diffie-Hellman elements with a KEM, managing asymmetric keys for the latter poses a problem when trying to preserve the authentication structure of EDHOC, namely a MAC derived from a long-term secret.
As proposed in {{I-D.pocero-authkem-edhoc}}, we go from 3 to 4 or 5 mandatory messages to achieve complete mutual authentication.
Here, we want to explore a different path. Our solution aims to strike a balance between the number of mandatory messages and the computations performed by each endpoint.


## First case: Initiator signs, Responder KEM and signs

We describe below the equivalent of EDHOC method 1. The Initiator will authenticate with a signature, and the Responder with a KEM and a signature.


### Protocol overview

~~~~~~~~~~
  I                                                             R
 ---                                                           ---
  |          METHOD, SUITES_I, kem.pk_eph, C_I, EAD_1           |
  +------------------------------------------------------------->
  |                          message_1                          |
  |                                                             |
  | kem.ct_eph, Enc(KEYSTREAM_2, ID_CRED_R, EAD_2), SIGNATURE_2 |
  <-------------------------------------------------------------+
  |                          message_2                          |
  |                                                             |
  |        kem.ct_R, AEAD(ID_CRED_I, Signature_3, EAD_3)        |
  +------------------------------------------------------------->
  |                          message_3                          |
  |                                                             |
  |                         AEAD(EAD_4)                         |
  <- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -+
  |                          message_4                          |
~~~~~~~~~~

Figure 3: PQ-EDHOC, I signs - R KEM & Signs message flow.


### Protocol description


#### Formatting and sending `message_1`

As in the usual EDHOC protocol, the first message (`message_1`) consists of:

  - `METHOD` --> as specified in {{RFC9528}} it is an integer specifying the authentication method the Initiator wants to use;
  - `SUITES_I` --> it consists of an ordered set of algorithms supported by the Initiator and formatted as specified in {{RFC9528}};
  - `C_I` (and also as `C_R`, which will appears later) --> the Connection Identifiers chosen by the Initiator (C_I) and by the Responder (`C_R`) as specified in {{RFC9528}};
  - `EAD_1` (and also `EAD_2`, `EAD_3` and `EAD_4`, which will appear later) -> External Authorization Data, respectively included in `message_1`, `message_2`, `message_3` (and optionally) `message_4`, and formatted as specified in {{RFC9528}};
  - `kem.pk_eph` --> the Ephemeral KEM public key generated by the Initiator;


#### Processing `message_1`, formatting and sending `message_2`

On the reception of the first message, the Responder proceeds as in the original EDHOC protocol with elements `METHOD`, `SUITES_I`, `C_I` and `EAD_1`.
In a second step, using `kem.pk_eph` and the `KEM.Encapsulation` algorithm, he computes the ephemeral ciphertext `kem.ct_eph` and the ephemeral shared-secret `ss_eph`.

The Responder select its Connection Identifier `C_R` as specified in {{RFC9528}}. He then computes:

  - `TH_2 = H(kem.ct_eph, H(message_1))`;

  - `PRK_2e = EDHOC_Extract(TH_2, ss_eph)` --> the salt SHALL be `TH_2` and the IKM SHALL be the ephemeral shared-secret `ss_eph`;

  - `KEYSTREAM_2 = EDHOC_KDF(PRK_2e, 0, TH_2, plaintext_length)`.

  - `SALT_3e2m = EDHOC_KDF(PRK_2e, 1, TH_2, hash_length)`.

The Responder now assembles `PLAINTEXT_2`:

  - `PLAINTEXT_2 = (C_R, ID_CRED_R, TH_2, EAD_2)`

then ciphers this message :

  - `CIPHERTEXT_2 = PLAINTEXT_2 XOR KEYSTREAM_2`

and finally signs this ciphertext:

  - `SIGNATURE_2 = DS.Sign(sign.sk_R, (CIPHERTEXT_2, sign_length))`


where `sign.sk_R` is the long-term signing private key of the Responder.


So the second message then consists of:

  - `kem.ct_eph` --> the ephemeral ciphertext obtained with `kem.pk_eph`;
  - `CIPHERTEXT_2`;
  - `SIGNATURE_2`.

**Important note:** let us mention that the element signed by the Responder, for security considerations during the security analysis, coulb be subject to slight changes. However, it serves here to illustrate the principle proposed here.

#### Processing `message_2`, formatting and sending `message_3`.

On reception of the second message, the Initiator, using `kemp.ct_eph`, can compute the ephemeral shared-secret `ss_eph`. As the Responder did, he computes `TH_2`, `PRK_2e` and `KEYSTREAM_2`. He can now decipher and retrieve : `PLAINTEXT_2 = CIPHERTEXT_2 XOR KEYSTREAM_2`.

Thanks to `ID_CRED_R`, the Initiator obtains the long-term KEM public keys of the Responder, `kemp.pk_R` and `sign.pk_R`.
At first, he checks the validity of the signature of the Responder:

  - `DS.Verify(sign.pk_R, (CIPHERTEXT_2 sign_length))`.

If the verification algorithm returns 1, the Initiator properly authenticated the Responder. Otherwise he aborts.

Assumong everything goes well, using the KEM encapsulation algorihtm `KEM.Encapsulation`, and the long-term input material `kem.pk_R` of the Responder, the Initiator generated the couple `(ss_R, kem.ct_R)`.

The shared-secret `ss_R` will then serve as IKM for the computation of `PRK_3e2m`:

  - `SALT_3e2m = EDHOC_KDF(PRK_2e, 1, TH_2, hash_length)`;

  - `PRK_3e2m = EDHOC_Extract(SALT_3e2m, ss_R)`.

It is now the turn of the Initiator to authenticate himself. To do so, he computes the following elements:

  - `TH_3 = H(TH_2, PLAINTEXT_2, ID_CRED_R)`;
  - `K_3 = EDHOC_KDF(PRK_3e2m, 3, TH_3, key_length)`;
  - `IV_3 = EDHOC_KDF(PRK_3e2m, 4, TH_3, iv_length)`;
  - `MAC_3 = EDHOC_KDF(PRK_3e2m, 6, ID_CRED_I, TH_3, EAD_3, mac_length_3)`

as in the original EDHOC procotol. Then comes the signature:

  - `SIGNATURE_3 = DS.Sign(sign.sk_I, (ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length))`

where `sign.sk_I` is the long-term signing private key of the Initiator.

Setting `PLAINTEXT_3 = (ID_CRED_I, SIGNATURE_3, EAD_3)`, the Initiator ciphers `PLAINTEXT_3` with the AEAD encryption algorithm negociated in `SUITES_I`.
The third message is then composed of:

  - `CIPHERTEXT_3`;
  - `kem.ct_R`.


#### Processing `message_3`

On reception of `message_3`, the Responder computes `TH_3`. He also used the `KEM.Decapsulation`algorithm with its long-term KEM private key `kem.sk_R`and the KEM ciphertext `kem.ct_R`, to obtain the shared-secret `ss_R`.

He can now compute `SALT_3e2m`, `PRK_3e2m`, `K_3`, and `IV_3` as the Initiator did, and deciphers `CIPHERTEXT_3` with the AEAD decryption algorithm.
With `PLAINTEXT_3`, he calculates `MAC_3`on his side, and verify the signature:

  - `DS.Verify(sign.pk_I, (ID_CRED_I, TH_3, EAD_3, MAC_3, sign_length))`

where `sign.pk_I` is the long-term signing public key of the Initiator. If the verification algorithm returns 1, the Initiator is properly authenticated to the Initiator. Otherwise the Responder aborts.


#### Optionally formatting, sending and recieving `message_4`

If the Responder decides of a fourth mandatory message, he then computes the following elements:

  - `TH_4 = H(TH_3, PLAINTEXT_3, ID_CRED_I)`;
  - `K_4 = EDHOC_KDF(PRK_4e3m, 8, TH_4, key_length)`;
  - `IV_4 = EDHOC_KDF(PRK_4e3m, 9, TH_4, iv_length)`.

Using the AEAD encryption algorithm, he ciphers `PLAINTEXT_4 = EAD_4`and sends it to the Initiator. The later computes `TH_4`, `K_4`, `IV_4`, and deciphers `CIPHERTEXT_4` thanks to the AEAD decryption algorithm.



#### Computing the session key `PRK_out`

Here again, it doesn't matter if there is a fourth mandatory message, in any case, both the Initiator and the Responder, in order to compute the key `PRK_out`, have to calcule the fourth transcript hash as in the original EDHOC protocol:

  - `TH_4 = H(TH_3, PLAINTEXT_3, ID_CRED_I)`.

With this element, using the EDHOC_KDF, they both obtain:

  - `PRK_out = EDHOC_KDF(PRK_3e2m, 7, TH_4, hash_length)`

which is the desired session key, and the authentication process is fully achieved.


### Associated key derivation schedule

In this section we present the key derivation schedule of the previously described protocol version.

~~~~~~~~~~
          +--------------------------------+
          |TH_2=H(kem.ct_eph, H(message_1))|
          +------+----------------------+--+              PLAINTEXT_1
                 |                      |                        |
  +------+   +---+---+   +------+   +---+--+   +-----------+   +-+-+
  |ss_eph|-->|Extract|-->|PRK_2e|-->|Expand|-->|KEYSTREAM_2|-->|XOR|
  +------+   +-------+   +---+--+   +---+--+   +-----------+   +-+-+
                             |                                   |
                             |                                   v
                             |                         +---------+--+
                             |                         |CIPHERTEXT_2|
                             |                         +------------+
                             |
                             |     +------+   +-----+   +-----------+
                             +-----|Expand|-->|MAC_2|-->|SIGNATURE_3|
                             |     +------+   +-----+   +-----------+
                             |
         +-----+---+   +---+--+
         |SALT_3e2m|<--|Expand|
         +-----+---+   +---+--+                           PLAINTEXT_3
               |                                               |
  +----+   +---+---+   +--------+   +------+   +--------+   +--+-+
  |ss_R|-->|Extract|-->|PRK_3e2m|-->|Expand|-->|K_3/IV_3|-->|AEAD|
  +----+   +-------+   +---+----+   +---+--+   +--------+   +--+-+
                           |            |                      |
                           |            |                      v
                           |            |              +-------+----+
                           |            |              |CIPHERTEXT_3|
                           |            |              +------------+
                           |            |
                           |   +--------+---------------------------+
                           |   |TH_3=H(TH_2, PLAINTEXT_2, ID_CRED_R)|
                           |   +------------------------------------+
                           |
                           |       +------+   +-----+   +-----------+
                           +-------|Expand|-->|MAC_3|-->|SIGNATURE_3|
                           |       +------+   +-----+   +-----------+
                           |
                           |                              PLAINTEXT_4
                           |                                   |
                           |        +------+   +--------+   +--+-+
               message_4?  +--------|Expand|-->|K_4/IV_4|-->|AEAD|
                           |        +---+--+   +--------+   +--+-+
                           |            |                      |
                           |            |                      v
                           |            |              +-------+----+
                           |            |              |CIPHERTEXT_4|
                           |            |              +------------+
                           |            |
                           |   +--------+---------------------------+
                           |   |TH_4=H(TH_3, PLAINTEXT_3, ID_CRED_I)|
                           |   +--------+---------------------------+
                           |            |
                           |            |
                           |        +---+--+   +-------+
                           +--------|Expand|-->|PRK_out|
                                    +------+   +-------+
~~~~~~~~~~
Figure 4: PQ-EDHOC, I signs - R KEM & Signs key derivation schedule.

### Analysis

TODO an analysis of the tradeoff, the protocol advantage and disadvantage (no mac on the Responder side, but a signature).


## Second case: Initiator KEM and signs, Responder signs


## Thrid case: Initiator and Responder KEM and sign


# Security Considerations


TODO Security


# IANA Considerations

This document has no IANA actions.


# Acknowledgments
TODO acknowledge.

--- back

