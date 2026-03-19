import '../models/vulnerability.dart';

/// CVSS v3.1 base score calculator.
///
/// Implements the deterministic formula from the CVSS v3.1 specification:
/// https://www.first.org/cvss/v3.1/specification-document
class CvssCalculator {
  // ---------------------------------------------------------------------------
  // Metric weights (CVSS v3.1 spec §7.1)
  // ---------------------------------------------------------------------------

  static const _av = {'NETWORK': 0.85, 'ADJACENT': 0.62, 'LOCAL': 0.55, 'PHYSICAL': 0.20};
  static const _ac = {'LOW': 0.77, 'HIGH': 0.44};
  static const _prUnchanged = {'NONE': 0.85, 'LOW': 0.62, 'HIGH': 0.27};
  static const _prChanged   = {'NONE': 0.85, 'LOW': 0.68, 'HIGH': 0.50};
  static const _ui = {'NONE': 0.85, 'REQUIRED': 0.62};
  static const _impact = {'NONE': 0.00, 'LOW': 0.22, 'HIGH': 0.56};

  /// Calculate CVSS v3.1 base score for a [Vulnerability].
  /// Returns null if required fields are missing or unrecognised.
  static double? calculate(Vulnerability v) {
    final av  = _av[v.attackVector.toUpperCase()];
    final ac  = _ac[v.attackComplexity.toUpperCase()];
    final scope = v.scope.toUpperCase();
    final prMap = scope == 'CHANGED' ? _prChanged : _prUnchanged;
    final pr  = prMap[v.privilegesRequired.toUpperCase()];
    final ui  = _ui[v.userInteraction.toUpperCase()];
    final c   = _impact[v.confidentialityImpact.toUpperCase()];
    final i   = _impact[v.integrityImpact.toUpperCase()];
    final a   = _impact[v.availabilityImpact.toUpperCase()];

    if (av == null || ac == null || pr == null || ui == null ||
        c == null || i == null || a == null) { return null; }

    // Impact sub-score (ISS)
    final iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a);
    if (iss == 0) { return 0.0; } // No impact → score is 0

    // Impact score
    final double impact;
    if (scope == 'UNCHANGED') {
      impact = 6.42 * iss;
    } else {
      impact = 7.52 * (iss - 0.029) - 3.25 * _pow(iss - 0.02, 15);
    }

    // Exploitability score
    final exploitability = 8.22 * av * ac * pr * ui;

    // Base score
    final double raw;
    if (scope == 'UNCHANGED') {
      raw = _min(impact + exploitability, 10.0);
    } else {
      raw = _min(1.08 * (impact + exploitability), 10.0);
    }

    return _roundUp(raw);
  }

  /// Returns a human-readable severity label for a numeric CVSS score.
  static String severityLabel(double score) {
    if (score >= 9.0) return 'CRITICAL';
    if (score >= 7.0) return 'HIGH';
    if (score >= 4.0) return 'MEDIUM';
    if (score > 0.0)  return 'LOW';
    return 'NONE';
  }

  /// Returns the CVSS v3.1 vector string for a vulnerability.
  static String vectorString(Vulnerability v) =>
      'CVSS:3.1/AV:${v.attackVector[0]}/AC:${v.attackComplexity[0]}'
      '/PR:${v.privilegesRequired[0]}/UI:${v.userInteraction[0]}'
      '/S:${v.scope[0]}/C:${v.confidentialityImpact[0]}'
      '/I:${v.integrityImpact[0]}/A:${v.availabilityImpact[0]}';

  // ---------------------------------------------------------------------------
  // Math helpers
  // ---------------------------------------------------------------------------

  static double _min(double a, double b) => a < b ? a : b;

  static double _pow(double base, int exp) {
    double result = 1.0;
    for (int i = 0; i < exp; i++) { result *= base; }
    return result;
  }

  /// CVSS roundup: rounds to 1 decimal place, always rounding up.
  static double _roundUp(double value) {
    final int100 = (value * 100000).round();
    if (int100 % 10000 == 0) return int100 / 100000;
    return ((int100 / 10000).ceil()) / 10;
  }
}
