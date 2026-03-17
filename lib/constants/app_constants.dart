import 'package:flutter/material.dart';

/// Application theme colors used across all screens and widgets.
class AppColors {
  static const background = Color(0xFF0A0E27);
  static const cardBackground = Color(0xFF1A1F3A);
  static const accent = Color(0xFF00F5FF);
  static const accentBlue = Color(0xFF0080FF);
  static const success = Color(0xFF00FF88);
  static const warning = Color(0xFFFFAA00);
  static const error = Color(0xFFFF0040);
  static const errorAlt = Color(0xFFFF0080);
  static const orange = Color(0xFFFF6B00);
}

/// Database settings keys.
class SettingsKeys {
  static const requireApproval = 'require_approval';
  static const maxIterations = 'max_iterations';
  static const temperature = 'temperature';
  static const maxTokens = 'maxTokens';
  static const timeoutSeconds = 'timeoutSeconds';
  static const modelName = 'modelName';
  static const provider = 'provider';
  static const baseUrl = 'baseUrl';
  static const apiKey = 'apiKey';
  static const storageBasePath = 'storage_base_path';
}

/// Default configuration values.
class ConfigDefaults {
  static const double temperature = 0.22;
  static const int maxTokens = 4096;
  static const int timeoutSeconds = 240;
  static const int maxIterations = 10;
}
