import 'dart:io';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

class StorageService {
  static String? _customBasePath;

  static void setCustomBasePath(String? path) {
    _customBasePath = path;
  }

  static Future<String> getBasePath() async {
    if (_customBasePath != null && _customBasePath!.isNotEmpty) {
      return _customBasePath!;
    }
    final docs = await getApplicationDocumentsDirectory();
    return p.join(docs.path, 'PenExecute');
  }

  static Future<String> getProjectPath(String projectName) async {
    final base = await getBasePath();
    final path = p.join(base, projectName);
    await Directory(path).create(recursive: true);
    return path;
  }

  static Future<String> getTargetPath(String projectName, String address) async {
    final project = await getProjectPath(projectName);
    final safe = address.replaceAll(RegExp(r'[^\w\.\-]'), '_');
    final path = p.join(project, safe);
    await Directory(path).create(recursive: true);
    return path;
  }

  /// Converts a native path to the form usable inside the shell that will
  /// actually execute commands (WSL bash on Windows, native path elsewhere).
  static String toShellPath(String nativePath) {
    if (!Platform.isWindows) return nativePath;
    // Convert Windows path to WSL mount path:
    // C:\Users\foo\bar  ->  /mnt/c/Users/foo/bar
    final normalized = nativePath.replaceAll('\\', '/');
    final match = RegExp(r'^([A-Za-z]):(.*)').firstMatch(normalized);
    if (match == null) return normalized;
    final drive = match.group(1)!.toLowerCase();
    final rest = match.group(2)!;
    return '/mnt/$drive$rest';
  }

  static Future<List<String>> listProjects() async {
    final base = await getBasePath();
    final dir = Directory(base);
    if (!await dir.exists()) return [];
    return dir
        .listSync()
        .whereType<Directory>()
        .map((d) => p.basename(d.path))
        .toList();
  }

  static Future<void> deleteProjectFolder(String projectName) async {
    final path = p.join(await getBasePath(), projectName);
    final dir = Directory(path);
    if (await dir.exists()) await dir.delete(recursive: true);
  }
}
