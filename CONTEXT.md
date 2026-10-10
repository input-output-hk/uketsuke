# Uketsuke

An inbox for one-off data collections from stake pools, independent of telemetry and reward membership.

## Language

**Pool**:
A stake pool contributing data to a **Campaign**.
_Avoid_: node, operator

**Operator**:
The person or organisation running a **Pool**.

**Pool ID**:
The on-chain identifier of a **Pool**.
_Avoid_: pool name, ticker

**Leios Key**:
A **Pool**'s BLS signing key registered on chain.
_Avoid_: cold key, pool identity key

**Key Roster**:
The trusted record of which **Leios Keys** the chain registers for each **Pool**.
_Avoid_: allowlist, reward membership

**Campaign**:
A named one-off data collection for a particular network and inbox destination.

**Submission**:
A ZIP report and its signed **Manifest**, attributed to a **Pool** through a **Leios Key** in the accepted **Key Roster**.
_Avoid_: telemetry submission

**Manifest**:
The signed description binding a **Submission** to its **Campaign**, **Pool**, identifier, report digest, size, display filename and expiry.

**Evidence**:
The signed **Manifest**, signing-key attestation naming the accepted **Key Roster** snapshot by epoch and slot, and **Receipt**, retained with a **Submission**.

**Bundle**:
One archival package containing a **Submission**'s untouched ZIP report and its **Evidence**.

**Archive**:
The authoritative store of accepted **Bundles**.
_Avoid_: staging, inbox working directory

**Receipt**:
The acknowledgement identifying a **Submission** accepted into the **Archive**.

## Relationships

- A **Pool** has as many **Leios Keys** as the accepted **Key Roster** lists for it.
- A **Submission** belongs to exactly one **Pool** and one **Campaign**.
- A **Leios Key** authenticates a **Submission** only where the accepted **Key Roster** associates it with the claimed **Pool ID**.
- A **Bundle** retains the exact signed **Manifest** and exact ZIP report, without normalization.
- A retry with the same Submission identifier and immutable Manifest fields recovers the same **Receipt**.
- **Campaign** participation does not require telemetry or reward membership.

## Example dialogue

> **Dev:** "Does a Pool's Leios Key determine where its report is filed?"
> **Domain expert:** "The key authenticates the Submission through the Key Roster; the Submission identifier identifies its Bundle, and a rotated key does not change that identity."
