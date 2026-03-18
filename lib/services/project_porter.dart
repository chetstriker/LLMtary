import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';
import 'package:archive/archive.dart';
import '../utils/file_dialog.dart';
import 'package:flutter/material.dart';
import 'package:pointycastle/export.dart';
import '../database/database_helper.dart';
import '../models/project.dart';
import '../models/target.dart';
import '../services/storage_service.dart';
import '../widgets/admin_password_dialog.dart';

class ProjectPorter {
  // ── Public API ─────────────────────────────────────────────────────────────

  static Future<void> exportProject(Project project, BuildContext context) async {
    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AdminPasswordDialog(mode: PasswordDialogMode.exportConfirm),
    );
    if (password == null || password.isEmpty) return;

    try {
      final zipBytes = await _buildZip(project);
      final encrypted = _encrypt(zipBytes, password);

      final savePath = await FileDialog.saveFile(
        dialogTitle: 'Export Project',
        fileName: '${project.name}.penex',
      );
      if (savePath == null) return;

      await File(savePath).writeAsBytes(encrypted);

      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Project exported to $savePath')),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Export failed: $e')),
        );
      }
    }
  }

  static Future<Project?> importProject(BuildContext context) async {
    final result = await FileDialog.pickFiles(
      dialogTitle: 'Import Project',
    );
    if (result == null || result.files.single.path == null) return null;

    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AdminPasswordDialog(mode: PasswordDialogMode.importSingle),
    );
    if (password == null || password.isEmpty) return null;

    try {
      final fileBytes = await File(result.files.single.path!).readAsBytes();
      final Uint8List zipBytes;
      try {
        zipBytes = _decrypt(fileBytes, password);
      } catch (_) {
        if (context.mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Incorrect password or corrupted file')),
          );
        }
        return null;
      }

      if (!context.mounted) return null;
      return await _extractAndImport(zipBytes, context);
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Import failed: $e')),
        );
      }
      return null;
    }
  }

  // ── ZIP builder ────────────────────────────────────────────────────────────

  static Future<Uint8List> _buildZip(Project project) async {
    final projectId = project.id!;
    final targets = await DatabaseHelper.getTargets(projectId);
    final vulns = await DatabaseHelper.getVulnerabilities(projectId);
    final cmdLogs = await DatabaseHelper.getCommandLogs(projectId);
    final promptMaps = await DatabaseHelper.getPromptLogs(projectId);
    final debugMaps = await DatabaseHelper.getDebugLogs(projectId);

    // Build address → portable path map
    final targetEntries = <Map<String, dynamic>>[];
    final fileEntries = <String, Uint8List>{};

    for (final t in targets) {
      final safeAddr = t.address.replaceAll(RegExp(r'[^\w\.\-]'), '_');
      final portablePath = 'files/$safeAddr/recon.json';
      targetEntries.add({
        'address': t.address,
        'jsonFilePath': portablePath,
        'summary': t.summary,
        'status': t.status.name,
      });
      if (t.jsonFilePath.isNotEmpty && await File(t.jsonFilePath).exists()) {
        fileEntries[portablePath] = await File(t.jsonFilePath).readAsBytes();
      }
      // Include all other files in the target directory
      final targetDir = Directory(t.jsonFilePath.isNotEmpty
          ? File(t.jsonFilePath).parent.path
          : '');
      if (targetDir.path.isNotEmpty && await targetDir.exists()) {
        await for (final entity in targetDir.list()) {
          if (entity is File && entity.path != t.jsonFilePath) {
            final fileName = entity.uri.pathSegments.last;
            fileEntries['files/$safeAddr/$fileName'] = await entity.readAsBytes();
          }
        }
      }
    }

    // Strip machine-specific IDs, cross-reference by address
    final addressById = {for (final t in targets) t.id: t.address};

    final vulnEntries = vulns
        .map((v) => {
              'targetAddress': v.targetAddress,
              'problem': v.problem,
              'cve': v.cve,
              'description': v.description,
              'severity': v.severity,
              'confidence': v.confidence,
              'evidence': v.evidence,
              'recommendation': v.recommendation,
              'attackVector': v.attackVector,
              'attackComplexity': v.attackComplexity,
              'privilegesRequired': v.privilegesRequired,
              'userInteraction': v.userInteraction,
              'scope': v.scope,
              'confidentialityImpact': v.confidentialityImpact,
              'integrityImpact': v.integrityImpact,
              'availabilityImpact': v.availabilityImpact,
              'vulnerabilityType': v.vulnerabilityType,
              'statusReason': v.statusReason,
              'proofCommand': v.proofCommand,
              'status': v.status.name,
            })
        .toList();

    final cmdEntries = cmdLogs
        .map((c) => {
              'targetAddress': addressById[c.targetId] ?? '',
              'timestamp': c.timestamp.toIso8601String(),
              'command': c.command,
              'output': c.output,
              'exitCode': c.exitCode,
              'vulnerabilityIndex': c.vulnerabilityIndex,
            })
        .toList();

    final promptEntries = promptMaps
        .map((m) => {
              'targetAddress': addressById[m['targetId'] as int?] ?? '',
              'prompt': m['prompt'],
              'response': m['response'],
              'timestamp': m['timestamp'],
            })
        .toList();

    final debugEntries = debugMaps
        .map((m) => {
              'targetAddress': addressById[m['targetId'] as int?] ?? '',
              'message': m['message'],
              'timestamp': m['timestamp'],
            })
        .toList();

    final manifest = {
      'penex_version': 1,
      'exported_at': DateTime.now().toUtc().toIso8601String(),
      'exported_from_os': Platform.operatingSystem,
      'project': {
        'name': project.name,
        'folderPath': '',
        'createdAt': project.createdAt.toIso8601String(),
        'lastOpenedAt': project.lastOpenedAt.toIso8601String(),
        'scanComplete': project.scanComplete,
        'analysisComplete': project.analysisComplete,
        'hasResults': project.hasResults,
      },
      'targets': targetEntries,
      'vulnerabilities': vulnEntries,
      'command_logs': cmdEntries,
      'prompt_logs': promptEntries,
      'debug_logs': debugEntries,
    };

    final archive = Archive();
    final manifestBytes = utf8.encode(const JsonEncoder.withIndent('  ').convert(manifest));
    archive.addFile(ArchiveFile('manifest.json', manifestBytes.length, manifestBytes));
    for (final entry in fileEntries.entries) {
      archive.addFile(ArchiveFile(entry.key, entry.value.length, entry.value));
    }

    return Uint8List.fromList(ZipEncoder().encode(archive)!);
  }

  // ── Encryption (AES-256-GCM, PBKDF2-SHA256) ───────────────────────────────

  static Uint8List _encrypt(Uint8List plaintext, String password) {
    final salt = _randomBytes(16);
    final iv = _randomBytes(12);
    final key = _deriveKey(password, salt);

    final cipher = GCMBlockCipher(AESEngine())
      ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));

    final ciphertext = cipher.process(plaintext);
    // ciphertext already includes the 16-byte GCM tag appended by pointycastle
    return Uint8List.fromList([...salt, ...iv, ...ciphertext]);
  }

  static Uint8List _decrypt(Uint8List data, String password) {
    if (data.length < 16 + 12 + 16) throw Exception('File too short');
    final salt = data.sublist(0, 16);
    final iv = data.sublist(16, 28);
    final ciphertext = data.sublist(28);
    final key = _deriveKey(password, salt);

    final cipher = GCMBlockCipher(AESEngine())
      ..init(false, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));

    return cipher.process(ciphertext); // throws InvalidCipherTextException on bad password
  }

  static Uint8List _deriveKey(String password, Uint8List salt) {
    final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
      ..init(Pbkdf2Parameters(salt, 200000, 32));
    return pbkdf2.process(utf8.encode(password) as Uint8List);
  }

  static Uint8List _randomBytes(int length) {
    final random = FortunaRandom();
    final seed = Uint8List(32);
    final now = DateTime.now().microsecondsSinceEpoch;
    for (var i = 0; i < 8; i++) {
      seed[i] = (now >> (i * 8)) & 0xFF;
    }
    // Mix in some extra entropy from the current time in nanoseconds
    final extra = DateTime.now().millisecondsSinceEpoch;
    for (var i = 0; i < 8; i++) {
      seed[8 + i] = (extra >> (i * 8)) & 0xFF;
    }
    random.seed(KeyParameter(seed));
    return random.nextBytes(length);
  }

  // ── Import extractor ───────────────────────────────────────────────────────

  static Future<Project?> _extractAndImport(Uint8List zipBytes, BuildContext context) async {
    final archive = ZipDecoder().decodeBytes(zipBytes);
    final manifestFile = archive.findFile('manifest.json');
    if (manifestFile == null) throw Exception('Invalid .penex file: missing manifest.json');

    final manifest = jsonDecode(utf8.decode(manifestFile.content as List<int>)) as Map<String, dynamic>;
    final projectData = manifest['project'] as Map<String, dynamic>;
    String projectName = projectData['name'] as String;

    // Check for name collision
    final existing = await DatabaseHelper.getProjects();
    if (existing.any((p) => p.name.toLowerCase() == projectName.toLowerCase())) {
      if (!context.mounted) return null;
      final renamed = await _promptRename(context, projectName);
      if (renamed == null) return null;
      projectName = renamed;
    }

    final folderPath = await StorageService.getProjectPath(projectName);
    final now = DateTime.now();

    // Insert project row
    final project = Project(
      name: projectName,
      folderPath: folderPath,
      createdAt: DateTime.tryParse(projectData['createdAt'] as String? ?? '') ?? now,
      lastOpenedAt: now,
      scanComplete: projectData['scanComplete'] as bool? ?? false,
      analysisComplete: projectData['analysisComplete'] as bool? ?? false,
      hasResults: projectData['hasResults'] as bool? ?? false,
    );
    final projectId = await DatabaseHelper.insertProject(project);
    final insertedProject = Project(
      id: projectId,
      name: project.name,
      folderPath: project.folderPath,
      createdAt: project.createdAt,
      lastOpenedAt: project.lastOpenedAt,
      scanComplete: project.scanComplete,
      analysisComplete: project.analysisComplete,
      hasResults: project.hasResults,
    );

    // Insert targets + write recon files, build address → targetId map
    final addressToTargetId = <String, int>{};
    final targetList = (manifest['targets'] as List? ?? []).cast<Map<String, dynamic>>();

    for (final t in targetList) {
      final address = t['address'] as String;
      final portablePath = t['jsonFilePath'] as String;
      final safeAddr = address.replaceAll(RegExp(r'[^\w\.\-]'), '_');
      final destDir = await StorageService.getTargetPath(projectName, address);
      final destPath = '$destDir/$safeAddr.json';

      // Write recon file if present in archive
      final fileEntry = archive.findFile(portablePath);
      if (fileEntry != null) {
        await File(destPath).writeAsBytes(fileEntry.content as List<int>);
      }

      // Restore all other files for this target from the archive
      final prefix = 'files/$safeAddr/';
      for (final entry in archive.files) {
        if (entry.name.startsWith(prefix) && entry.name != portablePath) {
          final fileName = entry.name.substring(prefix.length);
          if (fileName.isNotEmpty && !fileName.contains('/')) {
            await File('$destDir/$fileName').writeAsBytes(entry.content as List<int>);
          }
        }
      }

      final target = Target(
        projectId: projectId,
        address: address,
        jsonFilePath: fileEntry != null ? destPath : '',
        summary: t['summary'] as String? ?? '',
        status: TargetStatus.values.firstWhere(
          (e) => e.name == t['status'],
          orElse: () => TargetStatus.complete,
        ),
      );
      final targetId = await DatabaseHelper.insertTarget(projectId, target);
      addressToTargetId[address] = targetId;
    }

    // Insert vulnerabilities
    for (final v in (manifest['vulnerabilities'] as List? ?? []).cast<Map<String, dynamic>>()) {
      final addr = v['targetAddress'] as String? ?? '';
      final targetId = addressToTargetId[addr] ?? 0;
      final db = await DatabaseHelper.database;
      await db.insert('vulnerabilities', {
        'projectId': projectId,
        'targetId': targetId,
        'targetAddress': addr,
        'problem': v['problem'] ?? '',
        'cve': v['cve'] ?? '',
        'description': v['description'] ?? '',
        'severity': v['severity'] ?? '',
        'confidence': v['confidence'] ?? '',
        'evidence': v['evidence'] ?? '',
        'recommendation': v['recommendation'] ?? '',
        'attackVector': v['attackVector'] ?? 'NETWORK',
        'attackComplexity': v['attackComplexity'] ?? 'LOW',
        'privilegesRequired': v['privilegesRequired'] ?? 'NONE',
        'userInteraction': v['userInteraction'] ?? 'NONE',
        'scope': v['scope'] ?? 'UNCHANGED',
        'confidentialityImpact': v['confidentialityImpact'] ?? 'NONE',
        'integrityImpact': v['integrityImpact'] ?? 'NONE',
        'availabilityImpact': v['availabilityImpact'] ?? 'NONE',
        'vulnerabilityType': v['vulnerabilityType'] ?? '',
        'statusReason': v['statusReason'] ?? '',
        'proofCommand': v['proofCommand'],
        'status': v['status'] ?? 'pending',
      });
    }

    // Insert command logs
    for (final c in (manifest['command_logs'] as List? ?? []).cast<Map<String, dynamic>>()) {
      final addr = c['targetAddress'] as String? ?? '';
      final targetId = addressToTargetId[addr] ?? 0;
      final db = await DatabaseHelper.database;
      await db.insert('command_logs', {
        'projectId': projectId,
        'targetId': targetId,
        'timestamp': c['timestamp'] ?? now.toIso8601String(),
        'command': c['command'] ?? '',
        'output': c['output'] ?? '',
        'exitCode': c['exitCode'] ?? 0,
        'vulnerabilityIndex': c['vulnerabilityIndex'],
      });
    }

    // Insert prompt logs
    for (final p in (manifest['prompt_logs'] as List? ?? []).cast<Map<String, dynamic>>()) {
      final addr = p['targetAddress'] as String? ?? '';
      final targetId = addressToTargetId[addr] ?? 0;
      await DatabaseHelper.insertPromptLog(projectId, targetId, p['prompt'] as String? ?? '', p['response'] as String? ?? '');
    }

    // Insert debug logs
    for (final d in (manifest['debug_logs'] as List? ?? []).cast<Map<String, dynamic>>()) {
      final addr = d['targetAddress'] as String? ?? '';
      final targetId = addressToTargetId[addr] ?? 0;
      await DatabaseHelper.insertDebugLog(projectId, targetId, d['message'] as String? ?? '');
    }

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("Project '$projectName' imported successfully")),
      );
    }

    return insertedProject;
  }

  static Future<String?> _promptRename(BuildContext context, String originalName) async {
    final controller = TextEditingController(text: '$originalName (imported)');
    return showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: const Color(0xFF1A1F3A),
        title: const Text('Name Conflict', style: TextStyle(color: Color(0xFF00F5FF))),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text("A project named '$originalName' already exists. Import as:", style: const TextStyle(color: Colors.white70, fontSize: 13)),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              autofocus: true,
              style: const TextStyle(color: Colors.white),
              decoration: InputDecoration(
                enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: const Color(0xFF00F5FF).withValues(alpha: 0.4))),
                focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: Color(0xFF00F5FF))),
                filled: true,
                fillColor: const Color(0xFF0A0E27),
              ),
              onSubmitted: (v) => Navigator.of(ctx).pop(v.trim()),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('CANCEL', style: TextStyle(color: Colors.white54))),
          TextButton(onPressed: () => Navigator.of(ctx).pop(controller.text.trim()), child: const Text('IMPORT', style: TextStyle(color: Color(0xFF00F5FF)))),
        ],
      ),
    );
  }
}
