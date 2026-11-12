# Threat Model and Limitations

## 1. Byzantine validators in PBFT-style finalization

The simulator models a configured validator behavior and a `2f+1` vote threshold. Per-view vote locks prevent same-view equivocation by honest validators. The earlier cross-view test showed that locks scoped by view do not prevent different digests from receiving certificates in different views. The optional simulator final-outcome guard rejects a second conflicting application outcome after a certificate is reported, but it is centralized simulator state and does not repair the PBFT protocol. Full prepared certificates, persistent validator safety state, and safe VIEW-CHANGE/NEW-VIEW selection remain unimplemented.

## 2. Byzantine RSU as evidence source

Signatures detect altered or forged reports under the simulator's key model, and observation-root aggregation prevents repeated reports of one root from becoming multiple independent roots. A source can still withhold an observation or issue a signed false report within its modeled behavior. A report withheld before transmission is not observable to other participants. The evidence-source guard remains disabled by default and no new source policy is introduced here.

## 3. Byzantine evidence coordinator

The coordinator can send validators a selectively incomplete but internally valid bundle. Validators' deterministic requalification checks bundle consistency, not completeness. The current implementation has no independently maintained complete evidence inventory or redundant evidence commitment. As a result, completeness and the resulting qualification remain conditional on an honest coordinator. A Byzantine validator that also coordinates evidence means the prototype cannot claim end-to-end `f=1` Byzantine tolerance.

## Implemented guarantees and non-guarantees

- Implemented: signature verification for received attestations; root-aware independence; explicit conflict reporting and at-most-one accepted final digest per canonical case within a shared simulator guard instance; deterministic coordinator mapping as an opt-in experiment.
- Conditional: evidence completeness, on honest coordinator behavior and successful delivery of all available evidence.
- Not implemented: complete PBFT safety across views, distributed coordinator agreement/announcement, coordinator failover, detection of unannounced evidence, or protocol-wide Byzantine tolerance.

These limits are research-model assumptions, not claims about a deployed distributed system.
