# V-PUFT Research Framework v1.0.1

## Fixed

- Fixed `plot_weight_stability` when a skewed or small bootstrap sample places the arithmetic mean outside the percentile confidence interval.
- The plot now uses the bootstrap median as its centre and clips asymmetric error lengths at zero.
- Added a regression test reproducing the former `ValueError: yerr must not contain negative values`.

## Validation

- Full Python test suite passes.
- End-to-end demo passes with a reduced quick-check candidate/bootstrap configuration.
