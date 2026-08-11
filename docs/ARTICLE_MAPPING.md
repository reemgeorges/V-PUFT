# Ahmed et al. 2022 Mapping

Reference:

Ahmed, Di, and Mukathe, “A Blockchain-Enabled Incentive Trust Management with Threshold Ring Signature Scheme for Traffic Event Validation in VANETs,” Sensors 2022, 22(17), 6715. DOI: 10.3390/s22176715.

## Elements represented in this project

- vehicle witnesses
- threshold-style witness package
- RSU validation
- trust values for witness sources
- PBFT-based finalization
- blockchain/hash-linked recording
- event validation and malicious-vehicle revocation context

## Elements intentionally replaced by V-PUFT

- native article trust-decision rule
- simple witness counting as the final decision
- evidence acceptance without provenance-aware root de-correlation

## Elements not claimed as literal reimplementation

- threshold ring signature cryptographic construction
- incentive/payment mechanism with the article's exact formulas
- exact experimental parameters unavailable from a public original codebase

Therefore the model name is:

**Ahmed-Inspired Witness V-PUFT**

not:

**Ahmed Original Implementation**

The file `article_reference_ablation.csv` compares the article-style native witness-threshold indicator with the final V-PUFT decision inside the same witness architecture.
