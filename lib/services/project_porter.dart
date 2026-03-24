import 'dart:convert';
import 'dart:io';
import 'package:archive/archive.dart';
import '../utils/file_dialog.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:pointycastle/export.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import '../database/database_helper.dart';
import '../models/project.dart';
import '../models/target.dart';
import '../services/storage_service.dart';
import '../widgets/admin_password_dialog.dart';

// Top-level functions required by compute() (must be top-level or static)
Map<String, dynamic> _encryptIsolate(Map<String, dynamic> args) {
  final plaintext = args['plaintext'] as Uint8List;
  final password = args['password'] as String;
  final salt = args['salt'] as Uint8List;
  final iv = args['iv'] as Uint8List;
  final key = _deriveKeySync(password, salt);
  final cipher = GCMBlockCipher(AESEngine())
    ..init(true, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
  final ciphertext = cipher.process(plaintext);
  return {'salt': salt, 'iv': iv, 'ciphertext': ciphertext};
}

Uint8List _decryptIsolate(Map<String, dynamic> args) {
  final data = args['data'] as Uint8List;
  final password = args['password'] as String;
  if (data.length < 16 + 12 + 16) throw Exception('File too short');
  final salt = data.sublist(0, 16);
  final iv = data.sublist(16, 28);
  final ciphertext = data.sublist(28);
  final key = _deriveKeySync(password, salt);
  final cipher = GCMBlockCipher(AESEngine())
    ..init(false, AEADParameters(KeyParameter(key), 128, iv, Uint8List(0)));
  return cipher.process(ciphertext);
}

Uint8List _deriveKeySync(String password, Uint8List salt) {
  final pbkdf2 = PBKDF2KeyDerivator(HMac(SHA256Digest(), 64))
    ..init(Pbkdf2Parameters(salt, 200000, 32));
  return pbkdf2.process(utf8.encode(password));
}

class ProjectPorter {
  // ── Public API ─────────────────────────────────────────────────────────────

  static Future<void> exportProject(Project project, BuildContext context) async {
    final password = await showDialog<String>(
      context: context,
      barrierDismissible: false,
      builder: (_) => const AdminPasswordDialog(mode: PasswordDialogMode.exportConfirm),
    );
    if (password == null || password.isEmpty) return;

    if (!context.mounted) return;
    _showProgressDialog(context, 'Encrypting project…');

    try {
      debugPrint('[ProjectPorter] Building zip for "${project.name}"');
      final zipBytes = await _buildZip(project);
      debugPrint('[ProjectPorter] Zip built (${zipBytes.length} bytes), encrypting…');

      final salt = _randomBytes(16);
      final iv = _randomBytes(12);
      final result = await compute(_encryptIsolate, {
        'plaintext': zipBytes,
        'password': password,
        'salt': salt,
        'iv': iv,
      });
      final encrypted = Uint8List.fromList([
        ...result['salt'] as Uint8List,
        ...result['iv'] as Uint8List,
        ...result['ciphertext'] as Uint8List,
      ]);
      debugPrint('[ProjectPorter] Encryption complete (${encrypted.length} bytes)');

      if (context.mounted) Navigator.of(context, rootNavigator: true).pop();

      final savePath = await FileDialog.saveFile(
        dialogTitle: 'Export Project',
        fileName: '${project.name}.penex',
      );
      if (savePath == null) return;

      await File(savePath).writeAsBytes(encrypted);
      debugPrint('[ProjectPorter] Exported to $savePath');

      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Project exported to $savePath')),
        );
      }
    } catch (e, st) {
      debugPrint('[ProjectPorter] Export failed: $e\n$st');
      if (context.mounted) {
        Navigator.of(context, rootNavigator: true).pop();
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

    if (!context.mounted) return null;
    _showProgressDialog(context, 'Decrypting project…');

    try {
      debugPrint('[ProjectPorter] Reading file: ${result.files.single.path}');
      final fileBytes = await File(result.files.single.path!).readAsBytes();
      debugPrint('[ProjectPorter] File read (${fileBytes.length} bytes), decrypting…');

      final Uint8List zipBytes;
      try {
        zipBytes = await compute(_decryptIsolate, {
          'data': fileBytes,
          'password': password,
        });
        debugPrint('[ProjectPorter] Decryption successful (${zipBytes.length} bytes)');
      } catch (e) {
        debugPrint('[ProjectPorter] Decryption failed: $e');
        if (context.mounted) {
          Navigator.of(context, rootNavigator: true).pop();
          ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Incorrect password or corrupted file')),
          );
        }
        return null;
      }

      if (!context.mounted) return null;
      Navigator.of(context, rootNavigator: true).pop();
      _showProgressDialog(context, 'Importing project…');

      if (!context.mounted) return null;
      final project = await _extractAndImport(zipBytes, context);
      if (context.mounted) Navigator.of(context, rootNavigator: true).pop();
      return project;
    } catch (e, st) {
      debugPrint('[ProjectPorter] Import failed: $e\n$st');
      if (context.mounted) {
        Navigator.of(context, rootNavigator: true).pop();
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Import failed: $e')),
        );
      }
      return null;
    }
  }

  static void _showProgressDialog(BuildContext context, String message) {
    showDialog<void>(
      context: context,
      barrierDismissible: false,
      builder: (_) => PopScope(
        canPop: false,
        child: AlertDialog(
          backgroundColor: const Color(0xFF1A1F3A),
          content: Row(
            children: [
              const CircularProgressIndicator(color: Color(0xFF00F5FF)),
              const SizedBox(width: 20),
              Text(message, style: const TextStyle(color: Colors.white70)),
            ],
          ),
        ),
      ),
    );
  }

  // ── ZIP builder ────────────────────────────────────────────────────────────

  static Future<Uint8List> _buildZip(Project project) async {
    final projectId = project.id!;
    final targets = await DatabaseHelper.getTargets(projectId);
    final vulns = await DatabaseHelper.getVulnerabilities(projectId);
    final cmdLogs = await DatabaseHelper.getCommandLogs(projectId);
    final promptMaps = await DatabaseHelper.getPromptLogs(projectId);
    final debugMaps = await DatabaseHelper.getDebugLogs(projectId);
    final creds = await DatabaseHelper.getCredentialsByProject(projectId);

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
        'analysisComplete': t.analysisComplete,
        'executionComplete': t.executionComplete,
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

    final credEntries = creds
        .map((c) => {
              'service': c.service,
              'host': c.host,
              'username': c.username,
              'secret': c.secret,
              'secret_type': c.secretType,
              'source_vuln': c.sourceVuln,
              'discovered_at': c.discoveredAt.toIso8601String(),
            })
        .toList();

    final manifest = {
      'penex_version': 2,
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
        'first_analysis_at': project.firstAnalysisAt?.toIso8601String(),
        'last_execution_at': project.lastExecutionAt?.toIso8601String(),
        'report_title': project.reportTitle,
        'pentester_name': project.pentesterName,
        'executive_summary': project.executiveSummary,
        'methodology': project.methodology,
        'risk_rating_model': project.riskRatingModel,
        'conclusion': project.conclusion,
      },
      'targets': targetEntries,
      'vulnerabilities': vulnEntries,
      'command_logs': cmdEntries,
      'prompt_logs': promptEntries,
      'debug_logs': debugEntries,
      'credentials': credEntries,
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
      firstAnalysisAt: DateTime.tryParse(projectData['first_analysis_at'] as String? ?? ''),
      lastExecutionAt: DateTime.tryParse(projectData['last_execution_at'] as String? ?? ''),
      reportTitle: projectData['report_title'] as String?,
      pentesterName: projectData['pentester_name'] as String?,
      executiveSummary: projectData['executive_summary'] as String?,
      methodology: projectData['methodology'] as String?,
      riskRatingModel: projectData['risk_rating_model'] as String?,
      conclusion: projectData['conclusion'] as String?,
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
      firstAnalysisAt: project.firstAnalysisAt,
      lastExecutionAt: project.lastExecutionAt,
      reportTitle: project.reportTitle,
      pentesterName: project.pentesterName,
      executiveSummary: project.executiveSummary,
      methodology: project.methodology,
      riskRatingModel: project.riskRatingModel,
      conclusion: project.conclusion,
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
        analysisComplete: t['analysisComplete'] as bool? ?? false,
        executionComplete: t['executionComplete'] as bool? ?? false,
      );
      final targetId = await DatabaseHelper.insertTarget(projectId, target);
      addressToTargetId[address] = targetId;
    }

    final db = await DatabaseHelper.database;
    await db.transaction((txn) async {
      // Insert vulnerabilities
      for (final v in (manifest['vulnerabilities'] as List? ?? []).cast<Map<String, dynamic>>()) {
        final addr = v['targetAddress'] as String? ?? '';
        final targetId = addressToTargetId[addr] ?? 0;
        await txn.insert('vulnerabilities', {
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
        await txn.insert('command_logs', {
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
        await txn.insert('prompt_logs', {
          'projectId': projectId,
          'targetId': targetId,
          'prompt': p['prompt'] as String? ?? '',
          'response': p['response'] as String? ?? '',
          'timestamp': DateTime.now().toIso8601String(),
        });
      }

      // Insert debug logs
      for (final d in (manifest['debug_logs'] as List? ?? []).cast<Map<String, dynamic>>()) {
        final addr = d['targetAddress'] as String? ?? '';
        final targetId = addressToTargetId[addr] ?? 0;
        await txn.insert('debug_logs', {
          'projectId': projectId,
          'targetId': targetId,
          'message': d['message'] as String? ?? '',
          'timestamp': DateTime.now().toIso8601String(),
        });
      }

      // Insert credentials
      for (final c in (manifest['credentials'] as List? ?? []).cast<Map<String, dynamic>>()) {
        await txn.insert(
          'discovered_credentials',
          {
            'project_id': projectId,
            'service': c['service'] as String? ?? '',
            'host': c['host'] as String? ?? '',
            'username': c['username'] as String? ?? '',
            'secret': c['secret'] as String? ?? '',
            'secret_type': c['secret_type'] as String? ?? 'password',
            'source_vuln': c['source_vuln'] as String? ?? '',
            'discovered_at': DateTime.tryParse(c['discovered_at'] as String? ?? '')?.toIso8601String() ?? now.toIso8601String(),
          },
          conflictAlgorithm: ConflictAlgorithm.ignore,
        );
      }
    });

    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text("Project '$projectName' imported successfully")),
      );
    }

    // Recompute hasResults from imported vulnerability data — the stored flag
    // may be false even when confirmed findings exist (e.g. exported before
    // execution completed, or flag was never persisted).
    final importedVulns = (manifest['vulnerabilities'] as List? ?? []).cast<Map<String, dynamic>>();
    final hasConfirmed = importedVulns.any((v) => (v['status'] as String? ?? '') == 'confirmed');
    if (hasConfirmed && !insertedProject.hasResults) {
      await DatabaseHelper.updateProjectFlags(projectId, hasResults: true);
      return Project(
        id: insertedProject.id,
        name: insertedProject.name,
        folderPath: insertedProject.folderPath,
        createdAt: insertedProject.createdAt,
        lastOpenedAt: insertedProject.lastOpenedAt,
        scanComplete: insertedProject.scanComplete,
        analysisComplete: insertedProject.analysisComplete,
        hasResults: true,
        firstAnalysisAt: insertedProject.firstAnalysisAt,
        lastExecutionAt: insertedProject.lastExecutionAt,
        reportTitle: insertedProject.reportTitle,
        pentesterName: insertedProject.pentesterName,
        executiveSummary: insertedProject.executiveSummary,
        methodology: insertedProject.methodology,
        riskRatingModel: insertedProject.riskRatingModel,
        conclusion: insertedProject.conclusion,
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
