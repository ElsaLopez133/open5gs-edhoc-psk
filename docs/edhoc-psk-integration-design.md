# Integrating EDHOC-PSK into the 5G Core: Design and Implementation on Open5GS

## Abstract

This document describes the design, implementation, and rationale behind integrating the EDHOC-PSK (Ephemeral Diffie-Hellman Over COSE with Pre-Shared Key) key establishment protocol into the 5G core network as a proof-of-concept replacement for 5G-AKA authentication. The implementation is built on Open5GS and uses UERANSIM for UE-side testing. EDHOC-PSK and 5G-AKA follow fundamentally different paradigms: EDHOC is a general-purpose authenticated key establishment protocol designed to be embedded into any system, while 5G-AKA is a domain-specific authentication mechanism tightly integrated into the 3GPP architecture. Concretely, EDHOC is a lightweight two-party key establishment protocol (client/server), while 5G-AKA is a multi-party challenge-response mechanism distributed across Network Functions (NFs). This work maps EDHOC-PSK onto the existing 5G service-based architecture by defining the UE as EDHOC Initiator, the AUSF as EDHOC Responder, and the AMF as a transparent relay, while using the UDM/UDR path to provision EDHOC credentials from the subscriber database.

---

## 1. Introduction and Motivation

### 1.1 Background

5G networks authenticate subscribers using 5G-AKA (Authentication and Key Agreement), defined in 3GPP TS 33.501. This mechanism relies on symmetric credentials stored on USIM cards and in the UDM/UDR, with key derivation rooted in the Milenage or TUAK algorithms — cryptographic function sets (built on AES-128 and Keccak respectively) that run inside the USIM and in the UDM to produce authentication vectors (RES, CK, IK) from the permanent key K and a random challenge RAND. While proven and widely deployed, 5G-AKA is tightly coupled to the USIM ecosystem and the specific key hierarchy (K, CK, IK, KAUSF, KSEAF, KAMF).

EDHOC (Ephemeral Diffie-Hellman Over COSE, RFC 9528) is an IETF lightweight authenticated key establishment protocol designed for constrained environments. The EDHOC-PSK method (draft-ietf-lake-edhoc-psk) uses a pre-shared key for mutual authentication and establishes a fresh shared secret with forward secrecy. EDHOC is significantly lighter than protocols like TLS 1.3 or IKEv2, making it attractive for IoT and resource-constrained 5G devices.

### 1.2 Goal

The goal of this work is to demonstrate that EDHOC-PSK can serve as a viable alternative authentication mechanism within the 5G core, substituting 5G-AKA without requiring structural changes to the service-based architecture. This involves solving several mapping problems:

- **Structural mismatch**: EDHOC is a two-party protocol (Initiator/Responder); 5G authentication involves four entities in the authentication path (UE, AMF, AUSF, UDM).
- **Message count mismatch**: EDHOC-PSK requires four messages; 5G-AKA uses a single challenge-response round.
- **Key hierarchy mismatch**: EDHOC produces `PRK_out` via EDHOC-KDF; 5G-AKA produces CK, IK, KAUSF via Milenage/TUAK.
- **Transport mismatch**: EDHOC messages are compact CBOR byte strings with no pre-defined carrier in either the NAS protocol (the signaling protocol between UE and AMF, which defines specific IEs like RAND and AUTN for AKA) or the SBI (the HTTP/2-based REST API between core NFs, which uses OpenAPI-defined JSON models with no provision for arbitrary binary payloads).

### 1.3 Scope

This is a proof-of-concept implementation. It modifies Open5GS (core network) and UERANSIM (UE simulator) to run the EDHOC-PSK protocol end-to-end over the existing 5G infrastructure. It does not implement the EAP-EDHOC method (draft-ietf-emu-eap-edhoc), which is a separate protocol that wraps EDHOC inside a proper EAP method with its own registered EAP type, EAP state machine, and identity exchange. This implementation instead uses EAP Notification packets as a lightweight transport for raw EDHOC-PSK messages, and draws on the EAP-EDHOC specification only for key derivation guidance (EMSK via EDHOC_Exporter).

---

## 2. Architectural Mapping

### 2.1 Role Assignment

The fundamental design decision is how to map EDHOC's two-party model onto the 5G multi-NF architecture:

| EDHOC Role | 5G NF | Rationale |
|------------|-------|-----------|
| **Initiator** | UE | The UE initiates authentication, analogous to starting an EDHOC session. |
| **Responder** | AUSF | The AUSF is the authentication anchor in 5G. It holds session state and validates credentials, making it the natural EDHOC endpoint. |
| **Relay** | AMF | The AMF already relays NAS authentication messages between UE and core. In this design, it forwards EDHOC messages without inspecting their content. |
| **Credential provider** | UDM/UDR | The UDM retrieves subscriber EDHOC credentials (ID_CRED, PSK) from the UDR/MongoDB, paralleling its role in 5G-AKA where it retrieves K, OPc, and SQN. |

This mapping preserves the 5G trust model: the AMF never sees authentication secrets, and the UDM/UDR remains the authoritative source of subscriber credentials. The AUSF maintains EDHOC session state across multiple SBI round-trips.

### 2.2 Why the AMF is a Relay (Not a Participant)

In standard 5G-AKA, the AMF performs partial authentication validation (HXRES* verification) before forwarding the result to the AUSF. For EDHOC-PSK, the AMF cannot participate in the cryptographic exchange because:

1. The AMF does not hold PSK material (by design in 5G: credentials stay in AUSF/UDM).
2. EDHOC is a two-party protocol with no provision for a middlebox participant.
3. Keeping the AMF as a pure relay minimizes changes to the AMF codebase and preserves the existing security boundary.

The AMF stores incoming EDHOC payloads in a per-UE relay buffer and forwards them between the N1 (NAS) and N12 (SBI) interfaces without interpretation.

---

## 3. Protocol Flow

### 3.1 Overview

The EDHOC-PSK exchange requires four EDHOC messages plus a post-message_4 acknowledgment. This maps onto three NAS Authentication Request/Response round-trips, plus the initial context setup:

```
UE (Initiator)          AMF (Relay)            AUSF (Responder)         UDM/UDR
     |                      |                        |                      |
     |--- Registration ---->|                        |                      |
     |                      |--- N12: POST --------->|                      |
     |                      |   AuthenticationInfo   |--- N13: GET -------->|
     |                      |                        |   auth subscription  |
     |                      |                        |<-- kid, CRED_I, PSK -|
     |                      |<-- UeAuthCtx ----------|                      |
     |                      |   (auth_type=EDHOC_PSK)|                      |
     |                      |   (link: eap-session)  |                      |
     |                      |                        |                      |
     |<-- NAS Auth Req -----|                        |                      |
     |   (EDHOC-START)      |                        |                      |
     |                      |                        |                      |
     |--- NAS Auth Resp --->|                        |                      |
     |   (message_1)        |--- N12: PUT ---------->|                      |
     |                      |   eap-session          | process message_1    |
     |                      |   (message_1)          | generate message_2   |
     |                      |<-- ONGOING, message_2 -|                      |
     |<-- NAS Auth Req -----|                        |                      |
     |   (message_2)        |                        |                      |
     |                      |                        |                      |
     | process message_2    |                        |                      |
     | generate message_3   |                        |                      |
     |--- NAS Auth Resp --->|                        |                      |
     |   (message_3)        |--- N12: PUT ---------->|                      |
     |                      |   eap-session          | parse message_3      |
     |                      |   (message_3)          | resolve ID_CRED_I    |
     |                      |                        | verify message_3     |
     |                      |                        | derive KAUSF         |
     |                      |                        | generate message_4   |
     |                      |<-- ONGOING, message_4 -|                      |
     |<-- NAS Auth Req -----|                        |                      |
     |   (message_4)        |                        |                      |
     |                      |                        |                      |
     | process message_4    |                        |                      |
     |--- NAS Auth Resp --->|                        |                      |
     |   (empty ack)        |--- N12: PUT ---------->|                      |
     |                      |   eap-session          | auth = SUCCESS       |
     |                      |   (empty ack)          | compute KSEAF        |
     |                      |                        |--- auth result ----->|
     |                      |<-- SUCCESS, KSEAF -----|                      |
     |                      |                        |                      |
     |                      | derive KAMF from KSEAF |                      |
     |<-- Security Mode Cmd-|                        |                      |
     |--- Security Mode Cpl>|                        |                      |
     |<-- Registration Acc -|                        |                      |
```

### 3.2 Phase-by-Phase Description

#### Phase 0: Authentication Method Selection

When the UE sends a Registration Request, the AMF queries the AUSF, which queries the UDM. The UDM reads the subscriber's `authentication_method` field from the UDR (MongoDB). If the subscriber is provisioned with `EDHOC_PSK`, the UDM returns an `AuthenticationInfoResult` with `auth_type = EDHOC_PSK`, along with the subscriber's EDHOC credentials (kid and CRED_I in CCS format) carried in the `AuthenticationVector`.

This is the point at which the entire NF chain learns that this subscriber uses EDHOC instead of AKA. The decision propagates: UDM -> AUSF -> AMF, and each NF branches its logic accordingly.

#### Phase 1: Bootstrap (EDHOC-START)

Upon receiving `auth_type = EDHOC_PSK` from the AUSF, the AMF sends a NAS Authentication Request to the UE containing an EAP payload with a bootstrap marker (`EDHOC-START`). This bootstrap step is necessary because of a role inversion: in 5G-AKA, the network sends the first authentication payload (RAND and AUTN in the NAS Authentication Request), and the UE responds. In EDHOC-PSK, the UE is the Initiator and must generate message_1 first — but the 5G signaling flow always starts with the network sending a NAS Authentication Request to the UE. The EDHOC-START marker resolves this mismatch by telling the UE: "respond with EDHOC message_1 instead of an AKA RES*."

The AUSF stores the subscriber's EDHOC credentials in its UE context and provides the AMF with an `eap-session` link for subsequent round-trips.

#### Phase 2: message_1 and message_2

The UE, acting as EDHOC Initiator, generates `message_1` and sends it in a NAS Authentication Response. The AMF extracts the EAP payload and forwards it to the AUSF via the `eap-session` SBI endpoint.

The AUSF, acting as EDHOC Responder, processes `message_1` and generates `message_2`. It returns `message_2` to the AMF in a `ConfirmationDataResponse` with `auth_result = AUTHENTICATION_ONGOING`, signaling that the exchange is not yet complete. The AMF relays `message_2` to the UE in a new NAS Authentication Request.

#### Phase 3: message_3 and message_4

The UE processes `message_2`, generates `message_3`, and sends it back. The AMF relays it to the AUSF.

The AUSF parses `message_3`, resolves the UE's `ID_CRED_I` to the credential previously loaded from the UDM (matching by kid), verifies the message, and generates `message_4`. At this point, the EDHOC shared secret (`PRK_out`) is established, and the AUSF derives KAUSF (see Section 4). The AUSF returns `message_4` with `AUTHENTICATION_ONGOING`.

#### Phase 4: Post-message_4 Acknowledgment

After processing `message_4`, the UE sends an empty NAS Authentication Response. This serves as a signal to the AUSF that the UE has successfully completed the EDHOC exchange.

This acknowledgment step is not part of the core EDHOC-PSK specification, but is present in the EAP-EDHOC draft (draft-ietf-emu-eap-edhoc-08), where `message_4` acts as a protected success indication and the peer responds with an empty EAP-Response before receiving EAP-Success. In this implementation, the acknowledgment is necessary because the AUSF has no other mechanism to know that the UE successfully received and processed `message_4` before declaring authentication success. Without it, the AUSF would have to optimistically assume success after sending `message_4`, which breaks the confirmation semantics expected by the 5G key hierarchy.

Upon receiving the empty acknowledgment, the AUSF sets `auth_result = AUTHENTICATION_SUCCESS`, computes KSEAF from KAUSF, and returns the final `ConfirmationDataResponse` to the AMF. The AMF derives KAMF and proceeds with Security Mode Command.

---

## 4. Key Derivation

### 4.1 The Problem

5G-AKA derives its key hierarchy from USIM-rooted values:

```
K (permanent key on USIM)
  -> CK, IK (via Milenage/TUAK)
    -> KAUSF (via KDF with serving network name)
      -> KSEAF (via KDF)
        -> KAMF (via KDF with SUPI, ABBA)
```

EDHOC-PSK produces a completely different output: `PRK_out`, a pseudo-random key derived from the Diffie-Hellman exchange authenticated by the PSK. There is no CK or IK in EDHOC. The challenge is bridging EDHOC's output into the 5G key hierarchy at an appropriate injection point.

### 4.2 Approach: EDHOC_Exporter to KAUSF

The injection point chosen is KAUSF. This is the highest key in the 5G authentication key hierarchy that is authentication-method-specific. Everything below KAUSF (KSEAF, KAMF, NAS/AS keys) uses standardized 5G KDFs that are independent of the authentication method.

The derivation follows the approach outlined in the EAP-EDHOC specification (draft-ietf-emu-eap-edhoc-08, Section 5.3), adapted for the fact that this implementation does not use a full EAP method. The derivation produces an **EMSK (Extended Master Session Key)**, an EAP concept (RFC 3748, Section 7.10) — a 64-byte key that EAP methods export for use by higher-layer protocols. In 5G (TS 33.501, Section 6.1.3), KAUSF is derived from the EMSK for all EAP-based authentication methods:

```
EMSK = EDHOC_Exporter(label=27, context=empty, length=64)
KAUSF = EMSK[0:32]    (first 256 bits)
```

Where:
- **`EDHOC_Exporter`** is defined in RFC 9528, Section 4.2.1. It derives keying material from `PRK_exporter`, which is itself derived from `PRK_out` and the EDHOC transcript hash.
- **Label 27** is the IANA-suggested label for EMSK in EAP-EDHOC.
- **Empty context**: The EAP-EDHOC specification binds the EMSK to the EAP type code via the context parameter. Since this implementation does not use a registered EAP method (it reuses EAP Notification as a carrier rather than implementing a proper EAP-EDHOC type), the context is left empty. The EMSK is still bound to the EDHOC transcript (which includes both parties' ephemeral keys, credentials, and nonces), providing equivalent cryptographic binding.
- **KAUSF = EMSK[0:32]**: Following the 5G convention for EAP-based authentication methods (TS 33.501, Section 6.1.3), KAUSF is derived from the EMSK. The 256-bit truncation matches the standard KAUSF size.

Once KAUSF is established, the remaining key chain is unchanged:

```
KSEAF = KDF(KAUSF, serving_network_name)     [ogs_kdf_kseaf]
KAMF  = KDF(KSEAF, SUPI, ABBA)              [ogs_kdf_kamf]
```

### 4.3 Why Not CK/IK?

CK (Cipher Key) and IK (Integrity Key) are artifacts of the USIM/Milenage algorithm. They have no analog in EDHOC and are not needed. The 5G key hierarchy above KAMF only requires KAUSF as input; CK and IK are intermediate values used solely within the 5G-AKA derivation path. By injecting at KAUSF, EDHOC-PSK bypasses the CK/IK layer entirely.

### 4.4 Security Considerations for Key Derivation

<!-- POINT TO EXPAND: Discuss the security properties of this derivation:
     - Forward secrecy: EDHOC provides it via ephemeral DH; 5G-AKA does not.
     - Key confirmation: EDHOC message_3/message_4 provide mutual key confirmation;
       5G-AKA relies on HXRES*/RES* comparison.
     - Binding to serving network: The KSEAF derivation binds to serving_network_name,
       preserving the 5G anti-bidding-down property.
     - Empty context trade-off: Without EAP type binding, the EMSK is not bound to the
       transport method. Discuss whether this matters in practice (the EDHOC transcript
       already provides strong binding to the session).
-->

---

## 5. Transport: Carrying EDHOC over NAS and SBI

### 5.1 The Transport Problem

EDHOC messages are compact CBOR byte strings with no native carrier in either the NAS (N1) or SBI (N12) protocol stacks. Two transport problems must be solved:

1. **N1 (UE <-> AMF)**: NAS Authentication Request/Response messages carry AKA-specific fields (RAND, AUTN, RES*) or EAP payloads. There is no "generic binary" field.
2. **N12 (AMF <-> AUSF)**: The SBI `ConfirmationData` and `ConfirmationDataResponse` objects carry `resStar` and `kseaf` fields, with no provision for arbitrary protocol payloads.

### 5.2 N1 Transport: EAP Notification as Carrier

EDHOC messages are encapsulated in EAP packets using the EAP Notification type (Type 2), placed in the `eap_message` field of NAS Authentication Request/Response messages. The EAP packet structure:

```
+-------+------+--------+------+------------------+
| Code  |  ID  | Length | Type | EDHOC message    |
| 1 byte| 1 b  | 2 bytes| 1 b  | variable         |
+-------+------+--------+------+------------------+
  0x01    seq    total    0x02   message_1/2/3/4
  (Req)                  (Notif)
  0x02
  (Resp)
```

**Why EAP Notification?** This is a pragmatic choice to avoid defining new NAS IEs (Information Elements) or registering a new EAP type. EAP Notification is universally supported in NAS stacks, and the `eap_message` field is already defined in the NAS Authentication Request/Response specification. Creating a new carrier would require changes to the NAS encoder/decoder, the ASN.1 definitions, and potentially the gNB RRC layer, none of which are necessary for a proof-of-concept.

**EAP Notification (Type 2)** is defined in RFC 3748, Section 5.2, for the authenticator to send displayable text messages to the user (e.g., "your password will expire soon"). This implementation repurposes it to carry binary EDHOC messages — it works because the `eap_message` IE (Information Element type 0x78) in NAS Authentication Request/Response messages accepts any complete EAP packet regardless of EAP type, but it is semantically incorrect.

**Trade-off**: A production implementation has two proper alternatives: (1) implement the full EAP-EDHOC method (draft-ietf-emu-eap-edhoc), which defines a registered EAP type for EDHOC and would still use the existing `eap_message` NAS IE — this requires an EAP supplicant (a client-side EAP state machine handling method negotiation and identity exchange), which UERANSIM does not have; or (2) define a new NAS Information Element specifically for EDHOC payloads, which would require changes to the NAS specification (ASN.1 definitions, encoder/decoder) and potentially the gNB RRC layer.

### 5.3 N12 Transport: Extended SBI Models

On the SBI interface between AMF and AUSF, two model extensions carry EDHOC data:

**`AuthenticationVector` extension** (UDM -> AUSF, initial credential delivery):
- `edhoc_kid`: Hex-encoded subscriber key identifier (kid)
- `edhoc_cred_i_ccs_psk_hex`: Hex-encoded subscriber credential in CCS-PSK format

These fields are added alongside the existing AKA fields (`rand`, `autn`, `xres_star`, `kausf`), which are set to dummy values (`"00"`) for EDHOC.

**`ConfirmationDataResponse` extension** (AUSF -> AMF, EDHOC message relay):
- `edhoc_eap_payload`: Hex-encoded EAP packet containing the EDHOC response message (message_2 or message_4)

**`ConfirmationData` extension** (AMF -> AUSF, UE message relay):
- `eap_payload`: Hex-encoded EAP packet containing the UE's EDHOC message (message_1, message_3, or empty ack)

This is a dedicated field added to the `ConfirmationData` model, replacing the `resStar` field that is used in the 5G-AKA path.

### 5.4 Multi-Round SBI: AUTHENTICATION_ONGOING

Standard 5G-AKA uses a single PUT to the `5g-aka-confirmation` endpoint. EDHOC requires three PUTs to the same `eap-session` endpoint (message_1, message_3, empty ack). To support this, a new `auth_result` value is introduced:

- `AUTHENTICATION_ONGOING`: Indicates the EDHOC exchange is in progress. The AMF should relay the enclosed EDHOC payload to the UE and expect another NAS Authentication Response.
- `AUTHENTICATION_SUCCESS`: Final state, carries KSEAF. AMF proceeds to derive KAMF.
- `AUTHENTICATION_FAILURE`: Terminal error.

The AUSF maintains a state machine across SBI calls using two boolean flags per UE:

| State | `edhoc_in_progress` | `edhoc_waiting_message4_ack` | Next expected input |
|-------|-------------------|----------------------------|-------------------|
| Initial | `false` | `false` | message_1 |
| After message_1 processed | `true` | `false` | message_3 |
| After message_3 processed | `true` | `true` | empty ack |
| After ack received | `false` | `false` | (complete) |

---

## 6. Credential Management

### 6.1 Subscriber Provisioning

EDHOC-PSK credentials are stored in MongoDB alongside existing subscriber data. The subscriber document schema is extended:

```json
{
  "imsi": "001010000000001",
  "security": {
    "k": "...",
    "opc": "...",
    "amf": "8000"
  },
  "authentication_method": "EDHOC_PSK",
  "edhoc_credentials": [
    {
      "kid": "10",
      "cred_i_ccs_psk_hex": "A202696..."
    }
  ]
}
```

The `authentication_method` field determines which authentication path the UDM selects. When set to `EDHOC_PSK`, the UDM skips Milenage computation and instead returns the EDHOC credentials to the AUSF.

### 6.2 Credential Flow

```
MongoDB -> UDR -> UDM -> AUSF
  (edhoc_credentials)   (AuthenticationVector.edhoc_kid,
                          AuthenticationVector.edhoc_cred_i_ccs_psk_hex)
```

The AUSF caches the subscriber's kid and credential in its per-UE context. When processing message_3, the AUSF uses a credential resolver callback that:

1. Extracts the kid from the `ID_CRED_I` field in message_3 (CBOR map `{4: kid}`)
2. Matches it against the cached kid from the UDM
3. Returns the corresponding credential for EDHOC verification

### 6.3 AUSF Responder Credentials

The AUSF's own EDHOC identity (responder private key and credential) is configured in the AUSF YAML configuration file, loaded at startup via `ausf_context_parse_config()`.

<!-- POINT TO EXPAND: Discuss credential lifecycle, rotation, and how
     EDHOC credential management compares to USIM provisioning.
     Also discuss whether the kid could be derived from/linked to the SUPI. -->

---

## 7. Implementation Details

### 7.1 Modified Components

The implementation modifies the following Open5GS components:

**Core network (Open5GS):**

| Component | Files Modified | Changes |
|-----------|---------------|---------|
| AMF | `context.h`, `gmm-build.c`, `nausf-handler.c`, `nausf-build.c`, `gmm-handler.c` | EDHOC relay buffer, EAP payload in NAS Auth Req, ONGOING handling, auth type dispatch |
| AUSF | `context.h`, `nausf-handler.c`, `nudm-handler.c` | EDHOC responder state machine, Lakers integration, KAUSF derivation, credential caching |
| UDM | `nudr-handler.c` | EDHOC auth method selection, credential extraction from UDR |
| UDR | `nudr-handler.c` | Pass-through of EDHOC subscription fields |
| DBI (database) | `subscription.c`, `subscription.h` | Parse `edhoc_credentials` from MongoDB |
| OpenAPI models | `authentication_vector.{c,h}`, `confirmation_data_response.{c,h}`, `authentication_subscription.{c,h}` | Extension fields for EDHOC data |

**UE simulator (UERANSIM):**
- Modified NAS Authentication Request/Response handling to detect EDHOC-START, generate message_1/message_3, process message_2/message_4, and send the post-message_4 acknowledgment.

### 7.2 External Dependencies

- **lakers**: A Rust EDHOC library with C bindings, used for all EDHOC cryptographic operations (responder state machine, message generation/parsing, credential handling, EDHOC_Exporter). Linked into the AUSF binary.

### 7.3 Lines of Code and Footprint

<!-- POINT TO EXPAND: Quantify the implementation size:
     - Number of lines added/modified per component
     - Compare with the existing 5G-AKA code path size
     - Binary size impact of the lakers dependency
     This helps argue that EDHOC integration is feasible with modest changes. -->

---

## 8. Design Decisions and Trade-offs

### 8.1 Why Not Full EAP-EDHOC?

The EAP-EDHOC specification (draft-ietf-emu-eap-edhoc-08) defines a proper EAP method for EDHOC, complete with registered EAP type, session management, and key export. This implementation intentionally does not implement full EAP-EDHOC because:

1. **Scope**: The goal is to demonstrate EDHOC-PSK viability in 5G, not to implement a complete EAP method. The EAP framing is a transport convenience, not a protocol layer.
2. **Complexity**: A proper EAP implementation requires an EAP state machine on both UE and AUSF, EAP identity exchange, and method negotiation. This adds complexity without contributing to the core research question.
3. **UE modification**: UERANSIM does not include an EAP supplicant. Adding one is a significant effort orthogonal to the EDHOC integration.

However, the key derivation approach (EMSK via EDHOC_Exporter, label 27) follows the EAP-EDHOC specification to maintain alignment with the likely standardization path.

### 8.2 Why message_4 is Mandatory

In the base EDHOC specification (RFC 9528), message_4 is optional. However, in EDHOC-PSK (draft-ietf-lake-edhoc-psk), message_4 is **mandatory** — it is required for key confirmation because the PSK method needs explicit confirmation from the Responder. This mandatory status aligns well with the 5G architecture for two additional reasons:

1. **AUSF completion signal**: The AUSF needs to know when the UE has successfully completed the exchange before declaring `AUTHENTICATION_SUCCESS` and returning KSEAF to the AMF. Without message_4, the AUSF would have to declare success immediately after sending message_2's response (containing message_4), which is optimistic and does not confirm UE-side success.

2. **Alignment with EAP-EDHOC**: The EAP-EDHOC draft mandates message_4 as a "protected success indication." Following this pattern, even outside of EAP-EDHOC proper, ensures the flow is compatible with future standardization.

### 8.3 Why the Post-message_4 Acknowledgment Exists

EDHOC-PSK does not define a message after message_4. However, the SBI protocol is request-response: the AMF sends a PUT to the AUSF's `eap-session` endpoint and expects a response. To deliver message_4 to the UE, the AUSF must first return it to the AMF (in an `AUTHENTICATION_ONGOING` response), and the AMF must relay it to the UE. The UE then needs to send *something* back to the AMF so that the AMF can make a final PUT to the AUSF, triggering the `AUTHENTICATION_SUCCESS` response.

This is a consequence of the relay architecture: the AUSF cannot push messages directly to the UE. Every AUSF-to-UE message requires an AMF round-trip, and every AMF-to-AUSF message requires a UE trigger. The empty acknowledgment is the minimal UE response that completes this cycle.

### 8.4 Reuse vs. New Protocol Elements

This implementation prioritizes reuse of existing protocol elements over defining new ones:

| Element | Reused                                                          | Alternative (production) |
|---------|-----------------------------------------------------------------|--------------------------|
| NAS carrier | EAP Notification in Authentication Request                      | New NAS IE or proper EAP method |
| SBI endpoint | `eap-session` (existing)                                        | New EDHOC-specific endpoint |
| SBI payload (AMF->AUSF) | `ConfirmationData.eap_payload` (new field of an existing model) | Could use a dedicated EDHOC-specific message |
| Auth vector type | `EDHOC_PSK` (new enum value of an existing struct)              | Already proper |
| Auth result | Added `AUTHENTICATION_ONGOING`                                  | Could use HTTP 202 Accepted |

This approach minimizes the changeset and demonstrates feasibility. A production-grade integration would define proper protocol elements through 3GPP standardization.

---

## 9. Comparison with 5G-AKA

| Property | 5G-AKA                             | EDHOC-PSK (this work)                                              |
|----------|------------------------------------|--------------------------------------------------------------------|
| **Authentication rounds** | 1 (challenge-response)             | 3 NAS round-trips (4 EDHOC messages + ack)                         |
| **Forward secrecy** | No (keys derived from permanent K) | Yes (ephemeral DH exchange)                                        |
| **Credential type** | USIM (K, OPc, SQN)                 | Pre-shared key + kid                                               |
| **Key derivation root** | Milenage/TUAK -> CK, IK -> KAUSF   | EDHOC_Exporter -> EMSK -> KAUSF                                    |
| **NAS message overhead** | ~48 bytes (16B RAND + 16B AUTN + 16B RES*) | ~92 bytes total: message_1 (~37B), message_2 (~35B), message_3 (~11B), message_4 (~9B), plus 5B EAP framing per message |
| **Mutual authentication** | Via AUTN (network) + RES* (UE)     | Via EDHOC message_2/message_3/message_4 (complete after message_4) |
| **USIM dependency** | Required                           | Not required                                                       |
| **NF changes required** | None                               | AMF, AUSF, UDM, UDR, OpenAPI models                                |
| **UE changes required** | None                               | NAS layer modification                                             |

<!-- POINT TO EXPAND: Add performance measurements:
     - End-to-end authentication time (5G-AKA vs EDHOC-PSK)
     - Number of SBI messages exchanged
     - Bytes over N1 and N12
     - CPU time at AUSF for cryptographic operations
     These numbers strengthen the feasibility argument. -->

---

## 10. Limitations and Future Work

### 10.1 Current Limitations

1. **UE simulator only**: The UE side is implemented in UERANSIM, not on real hardware. Testing with a real UE (e.g., a software-defined radio-based UE or a modified modem firmware) would validate the NAS-level interoperability.

2. **Single credential per subscriber**: The current MongoDB schema supports an array of `edhoc_credentials`, but only the first entry is used.

3. **No EDHOC error handling**: EDHOC defines an error message type for signaling failures. The current implementation treats any unexpected message as `AUTHENTICATION_FAILURE` without sending EDHOC error messages back to the peer.

4. **No re-authentication or key refresh**: The implementation handles initial authentication only. 5G supports re-authentication via stored security contexts; the EDHOC equivalent (re-running the exchange or using EDHOC's key update mechanism) is not implemented.

5. **EAP carrier limitations**: EAP Notification is not designed for binary protocol transport. Message size is limited by the EAP Length field (16-bit, max 65535 bytes), though EDHOC messages are well within this limit.

6. **Empty EDHOC_Exporter context**: Because no EAP type code is used, the EMSK is not bound to a transport method identifier. This is acceptable for a PoC but should be addressed in a production implementation.

### 10.2 Future Work

1. **Real UE testing**: Port the EDHOC initiator logic to a real UE platform to validate over-the-air operation with Open5GS.

2. **Performance benchmarking**: Measure authentication latency, signaling overhead, and computational cost compared to 5G-AKA. The additional round-trips are the main cost; EDHOC's lightweight cryptography may partially offset this.

5. **Integration with 5G security procedures**: Investigate how EDHOC interacts with other 5G security features: SUCI concealment, key set identifier management, horizontal/vertical key derivation, and inter-system handover.

6. **Formal security analysis**: Analyze the composed protocol (EDHOC within 5G NAS/SBI) for security properties, particularly whether the relay architecture preserves EDHOC's proven guarantees.

<!-- POINT TO EXPAND: For the thesis, consider:
     - A formal threat model for EDHOC-in-5G (what attacks does this resist
       that 5G-AKA doesn't, and vice versa?)
     - Discussion of how this relates to 3GPP's own work on alternative
       authentication methods (TS 33.535 for non-3GPP access, etc.)
     - Comparison with other lightweight auth proposals for IoT-5G
       (e.g., EAP-TLS 1.3, EAP-NOOB)
-->

---

## 11. Conclusion

This work demonstrates that EDHOC-PSK can be integrated into the 5G core network as an alternative to 5G-AKA with relatively contained modifications to the existing architecture. The key design choices -- AMF as relay, AUSF as EDHOC responder, KAUSF injection via EDHOC_Exporter -- preserve the 5G trust model and key hierarchy while substituting the underlying authentication mechanism. The proof-of-concept runs end-to-end on Open5GS with UERANSIM, completing subscriber registration with EDHOC-derived keys.

The main cost is the increased signaling: three NAS round-trips versus one for 5G-AKA. The main benefit is forward secrecy and independence from the USIM ecosystem, which is relevant for IoT deployments where traditional USIM provisioning is impractical.

---

## References

- **RFC 9528**: Selander, G., Mattsson, J.P., and F. Palombini, "Ephemeral Diffie-Hellman Over COSE (EDHOC)", RFC 9528, 2024.
- **draft-ietf-lake-edhoc-psk**: Selander, G., Mattsson, J.P., and M. Vucinic, "EDHOC PSK authentication", draft-ietf-lake-edhoc-psk.
- **draft-ietf-emu-eap-edhoc-08**: Ingemarsson, G., and M. Vucinic, "EAP-EDHOC", draft-ietf-emu-eap-edhoc-08.
- **3GPP TS 33.501**: "Security architecture and procedures for 5G System", v15.9.0.
- **3GPP TS 29.509**: "Authentication Server Services", v16.
- **Open5GS**: Open-source 5G core network implementation, https://open5gs.org.
- **UERANSIM**: Open-source 5G UE and RAN simulator, https://github.com/aligungr/UERANSIM.
- **lakers**: Rust EDHOC library, https://github.com/openwsn-berkeley/lakers.
