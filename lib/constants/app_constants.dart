import 'package:flutter/material.dart';

/// Application theme colors used across all screens and widgets.
class AppColors {
  static const background = Color(0xFF0D0F1A);
  static const cardBackground = Color(0xFF161929);
  static const navBackground = Color(0xFF0A0C16);
  static const accent = Color(0xFF7C5CFC);
  static const accentBlue = Color(0xFF5B8DEF);
  static const accentGlow = Color(0xFF9B7DFF);
  static const success = Color(0xFF3DFFA0);
  static const warning = Color(0xFFFFBB33);
  static const error = Color(0xFFFF4466);
  static const errorAlt = Color(0xFFFF2D6B);
  static const orange = Color(0xFFFF8C42);
  static const dotColor = Color(0xFF1E2235);
}

/// Database settings keys.
class SettingsKeys {
  static const requireApproval = 'require_approval';
  static const temperature = 'temperature';
  static const maxTokens = 'maxTokens';
  static const timeoutSeconds = 'timeoutSeconds';
  static const modelName = 'modelName';
  static const provider = 'provider';
  static const baseUrl = 'baseUrl';
  static const apiKey = 'apiKey';
  static const storageBasePath = 'storage_base_path';
  static const String maxIterations = 'maxIterations';
}

/// Default configuration values.
class ConfigDefaults {
  static const double temperature = 0.22;
  static const int maxTokens = 8000;
  static const int timeoutSeconds = 300;
  static const int maxIterations = 25;
}
