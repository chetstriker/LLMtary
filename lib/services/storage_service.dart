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
