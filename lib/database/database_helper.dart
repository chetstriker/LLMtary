import 'package:flutter/foundation.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';
import '../models/target.dart';
import '../models/project.dart';
import '../models/credential.dart';

class DatabaseHelper {
  static Future<Database>? _initFuture;

  static Future<Database> get database async {
    _initFuture ??= _initDatabase();
    return _initFuture!;
  }

  static Future<Database> _initDatabase() async {
    debugPrint('[DB] _initDatabase() called');
    final appDir = await getApplicationSupportDirectory();
    debugPrint('[DB] appSupportDir=${appDir.path}');
    await appDir.create(recursive: true);
    debugPrint('[DB] directory ensured');
    final path = join(appDir.path, 'penexecute.db');
    debugPrint('[DB] opening database at $path');

    final db = await openDatabase(
      path,
      version: 17,
      singleInstance: false,
      onConfigure: (db) async {
        await db.execute('PRAGMA busy_timeout=5000');
        debugPrint('[DB] onConfigure: busy_timeout set');
      },
      onCreate: (db, version) async {
        debugPrint('[DB] onCreate: creating fresh schema at version $version');
        await db.execute('''
          CREATE TABLE vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            problem TEXT NOT NULL,
            cve TEXT,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL,
            evidence TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            attackVector TEXT,
            attackComplexity TEXT,
            privilegesRequired TEXT,
            userInteraction TEXT,
            scope TEXT,
            confidentialityImpact TEXT,
            integrityImpact TEXT,
            availabilityImpact TEXT,
            vulnerabilityType TEXT,
            businessRisk TEXT DEFAULT '',
            statusReason TEXT,
            proofCommand TEXT,
            proofCommandExpectedOutput TEXT,
            proofOutput TEXT,
            reproductionSteps TEXT,
            confirmedAt TEXT,
            targetAddress TEXT DEFAULT '',
            targetId INTEGER DEFAULT 0,
            projectId INTEGER DEFAULT 0,
            status TEXT NOT NULL,
            remediationClass TEXT NOT NULL DEFAULT 'unclassified'
          )
        ''');

        await db.execute('''
          CREATE TABLE command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            command TEXT NOT NULL,
            output TEXT NOT NULL,
            exitCode INTEGER NOT NULL,
            vulnerabilityIndex INTEGER,
            projectId INTEGER DEFAULT 0,
            targetId INTEGER DEFAULT 0
          )
        ''');

        await db.execute('''
          CREATE TABLE projects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            folderPath TEXT NOT NULL,
            createdAt TEXT NOT NULL,
            lastOpenedAt TEXT NOT NULL,
            scanComplete INTEGER NOT NULL DEFAULT 0,
            analysisComplete INTEGER NOT NULL DEFAULT 0,
            hasResults INTEGER NOT NULL DEFAULT 0,
            first_analysis_at TEXT,
            last_execution_at TEXT,
            report_title TEXT,
            pentester_name TEXT,
            executive_summary TEXT,
            methodology TEXT,
            risk_rating_model TEXT,
            conclusion TEXT,
            scope TEXT,
            scope_exclusions TEXT,
            scope_notes TEXT
          )
        ''');

        await db.execute('''
          CREATE TABLE discovered_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project_id INTEGER NOT NULL,
            service TEXT NOT NULL,
            host TEXT NOT NULL,
            username TEXT NOT NULL,
            secret TEXT NOT NULL,
            secret_type TEXT NOT NULL DEFAULT 'password',
            source_vuln TEXT,
            discovered_at TEXT NOT NULL,
            credential_source TEXT NOT NULL DEFAULT 'extractedFromOutput',
            FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
            UNIQUE(project_id, service, host, username, secret)
          )
        ''');

        await db.execute('''
          CREATE TABLE targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            projectId INTEGER NOT NULL,
            address TEXT NOT NULL,
            jsonFilePath TEXT NOT NULL,
            summary TEXT,
            status TEXT NOT NULL,
            analysisComplete INTEGER NOT NULL DEFAULT 0,
            executionComplete INTEGER NOT NULL DEFAULT 0
          )
        ''');

        await db.execute('''
          CREATE TABLE prompt_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            projectId INTEGER NOT NULL,
            targetId INTEGER NOT NULL,
            prompt TEXT NOT NULL,
            response TEXT NOT NULL,
            timestamp TEXT NOT NULL
          )
        ''');

        await db.execute('''
          CREATE TABLE debug_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            projectId INTEGER NOT NULL,
            targetId INTEGER NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
          )
        ''');

        await db.execute('''
          CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          )
        ''');

        await db.execute('''
          CREATE TABLE command_whitelist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT NOT NULL UNIQUE COLLATE NOCASE,
            added_at TEXT NOT NULL
          )
        ''');

        await db.execute('''
          CREATE TABLE executed_commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            projectId INTEGER NOT NULL,
            targetId INTEGER NOT NULL,
            command_normalized TEXT NOT NULL,
            output TEXT NOT NULL DEFAULT '',
            exit_code INTEGER NOT NULL DEFAULT -1,
            executed_at TEXT NOT NULL,
            UNIQUE(projectId, targetId, command_normalized)
          )
        ''');

        await db.execute(
          'CREATE INDEX IF NOT EXISTS idx_exec_cmds ON executed_commands(projectId, targetId)'
        );

        await db.execute('''
          CREATE TABLE provider_settings (
            provider TEXT PRIMARY KEY,
            baseUrl TEXT,
            apiKey TEXT,
            modelName TEXT,
            temperature REAL,
            maxTokens INTEGER,
            timeoutSeconds INTEGER
          )
        ''');
      },
      onUpgrade: (db, oldVersion, newVersion) async {
        debugPrint('[DB] onUpgrade: $oldVersion → $newVersion');
        if (oldVersion < 2) {
          await db.execute('ALTER TABLE vulnerabilities ADD COLUMN vulnerabilityType TEXT');
        }
        if (oldVersion < 3) {
          await db.execute('ALTER TABLE vulnerabilities ADD COLUMN statusReason TEXT');
          await db.execute('ALTER TABLE vulnerabilities ADD COLUMN proofCommand TEXT');
        }
        if (oldVersion < 4) {
          await db.execute('ALTER TABLE command_logs ADD COLUMN vulnerabilityIndex INTEGER');
        }
        if (oldVersion < 5) {
          await db.execute('''
            CREATE TABLE IF NOT EXISTS command_whitelist (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              command TEXT NOT NULL UNIQUE COLLATE NOCASE,
              added_at TEXT NOT NULL
            )
          ''');
        }
        if (oldVersion < 6) {
          await db.execute('''
            CREATE TABLE IF NOT EXISTS provider_settings (
              provider TEXT PRIMARY KEY,
              baseUrl TEXT,
              apiKey TEXT,
              modelName TEXT,
              temperature REAL,
              maxTokens INTEGER,
              timeoutSeconds INTEGER
            )
          ''');
        }
        if (oldVersion < 8) {
          await db.execute('ALTER TABLE vulnerabilities ADD COLUMN targetAddress TEXT DEFAULT \'\'');
          await db.execute('ALTER TABLE vulnerabilities ADD COLUMN targetId INTEGER DEFAULT 0');
          await db.execute('ALTER TABLE vulnerabilities ADD COLUMN projectId INTEGER DEFAULT 0');
          await db.execute('ALTER TABLE command_logs ADD COLUMN projectId INTEGER DEFAULT 0');
          await db.execute('ALTER TABLE command_logs ADD COLUMN targetId INTEGER DEFAULT 0');
          await db.execute('''
            CREATE TABLE IF NOT EXISTS projects (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              folderPath TEXT NOT NULL,
              createdAt TEXT NOT NULL,
              lastOpenedAt TEXT NOT NULL,
              scanComplete INTEGER NOT NULL DEFAULT 0,
              analysisComplete INTEGER NOT NULL DEFAULT 0,
              hasResults INTEGER NOT NULL DEFAULT 0
            )
          ''');
          await db.execute('''
            CREATE TABLE IF NOT EXISTS targets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              projectId INTEGER NOT NULL,
              address TEXT NOT NULL,
              jsonFilePath TEXT NOT NULL,
              summary TEXT,
              status TEXT NOT NULL
            )
          ''');
          await db.execute('''
            CREATE TABLE IF NOT EXISTS prompt_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              projectId INTEGER NOT NULL,
              targetId INTEGER NOT NULL,
              prompt TEXT NOT NULL,
              response TEXT NOT NULL,
              timestamp TEXT NOT NULL
            )
          ''');
          await db.execute('''
            CREATE TABLE IF NOT EXISTS debug_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              projectId INTEGER NOT NULL,
              targetId INTEGER NOT NULL,
              message TEXT NOT NULL,
              timestamp TEXT NOT NULL
            )
          ''');
        }
        if (oldVersion < 9) {
          await db.execute('ALTER TABLE targets ADD COLUMN analysisComplete INTEGER NOT NULL DEFAULT 0');
          await db.execute('ALTER TABLE targets ADD COLUMN executionComplete INTEGER NOT NULL DEFAULT 0');
        }
        if (oldVersion < 10) {
          await db.execute('''
            CREATE TABLE IF NOT EXISTS executed_commands (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              projectId INTEGER NOT NULL,
              targetId INTEGER NOT NULL,
              command_normalized TEXT NOT NULL,
              executed_at TEXT NOT NULL,
              UNIQUE(projectId, targetId, command_normalized)
            )
          ''');
          await db.execute(
            'CREATE INDEX IF NOT EXISTS idx_exec_cmds ON executed_commands(projectId, targetId)'
          );
        }
        if (oldVersion < 11) {
          // Add output caching columns — ignore errors if columns already exist
          try { await db.execute('ALTER TABLE executed_commands ADD COLUMN output TEXT NOT NULL DEFAULT \'\''); } catch (_) {}
          try { await db.execute('ALTER TABLE executed_commands ADD COLUMN exit_code INTEGER NOT NULL DEFAULT -1'); } catch (_) {}
        }
        if (oldVersion < 12) {
          await db.execute('ALTER TABLE projects ADD COLUMN first_analysis_at TEXT');
          await db.execute('ALTER TABLE projects ADD COLUMN last_execution_at TEXT');
          await db.execute('''
            CREATE TABLE IF NOT EXISTS discovered_credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              project_id INTEGER NOT NULL,
              service TEXT NOT NULL,
              host TEXT NOT NULL,
              username TEXT NOT NULL,
              secret TEXT NOT NULL,
              secret_type TEXT NOT NULL DEFAULT 'password',
              source_vuln TEXT,
              discovered_at TEXT NOT NULL,
              FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
              UNIQUE(project_id, service, host, username, secret)
            )
          ''');
        }
        if (oldVersion < 13) {
          await db.execute('ALTER TABLE projects ADD COLUMN report_title TEXT');
          await db.execute('ALTER TABLE projects ADD COLUMN pentester_name TEXT');
          await db.execute('ALTER TABLE projects ADD COLUMN executive_summary TEXT');
          await db.execute('ALTER TABLE projects ADD COLUMN methodology TEXT');
          await db.execute('ALTER TABLE projects ADD COLUMN risk_rating_model TEXT');
          await db.execute('ALTER TABLE projects ADD COLUMN conclusion TEXT');
        }
        if (oldVersion < 14) {
          await db.execute("ALTER TABLE vulnerabilities ADD COLUMN businessRisk TEXT DEFAULT ''");
        }
        if (oldVersion < 15) {
          // Vulnerabilities: PoC artifact fields
          try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN proofOutput TEXT'); } catch (_) {}
          try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN reproductionSteps TEXT'); } catch (_) {}
          try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN confirmedAt TEXT'); } catch (_) {}
          // Credentials: source tracking
          try { await db.execute("ALTER TABLE discovered_credentials ADD COLUMN credential_source TEXT NOT NULL DEFAULT 'extractedFromOutput'"); } catch (_) {}
          // Projects: scope/engagement fields
          try { await db.execute('ALTER TABLE projects ADD COLUMN scope TEXT'); } catch (_) {}
          try { await db.execute('ALTER TABLE projects ADD COLUMN scope_exclusions TEXT'); } catch (_) {}
          try { await db.execute('ALTER TABLE projects ADD COLUMN scope_notes TEXT'); } catch (_) {}
        }
        if (oldVersion < 16) {
          try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN proofCommandExpectedOutput TEXT'); } catch (_) {}
        }
        if (oldVersion < 17) {
          try { await db.execute("ALTER TABLE vulnerabilities ADD COLUMN remediationClass TEXT NOT NULL DEFAULT 'unclassified'"); } catch (_) {}
        }
      },
    );
    final version = await db.getVersion();
    debugPrint('[DB] openDatabase() returned successfully, schema version=$version');
    return db;
  }

  static Future<int> insertVulnerability(Vulnerability vuln) async {
    final db = await database;
    return await db.insert('vulnerabilities', vuln.toMap());
  }

  static Future<List<Vulnerability>> getVulnerabilities(int projectId) async {
    final db = await database;
    final maps = await db.query('vulnerabilities', where: 'projectId = ?', whereArgs: [projectId]);
    return maps.map((map) => Vulnerability.fromMap(map)).toList();
  }

  static Future<void> updateVulnerability(Vulnerability vuln) async {
    final db = await database;
    await db.update('vulnerabilities', vuln.toMap(), where: 'id = ?', whereArgs: [vuln.id]);
  }

  static Future<void> updateVulnerabilityStatus(int id, VulnerabilityStatus status) async {
    final db = await database;
    await db.update('vulnerabilities', {'status': status.name}, where: 'id = ?', whereArgs: [id]);
  }

  static Future<void> clearVulnerabilities() async {
    final db = await database;
    await db.delete('vulnerabilities');
  }

  static Future<int> insertCommandLog(CommandLog log) async {
    final db = await database;
    return await db.insert('command_logs', log.toMap());
  }

  static Future<List<CommandLog>> getCommandLogs(int projectId) async {
    final db = await database;
    final maps = await db.query('command_logs', where: 'projectId = ?', whereArgs: [projectId], orderBy: 'timestamp DESC');
    return maps.map((map) => CommandLog.fromMap(map)).toList();
  }

  static Future<void> clearCommandLogs() async {
    final db = await database;
    await db.delete('command_logs');
  }

  static Future<void> saveSetting(String key, String value) async {
    final db = await database;
    await db.insert('settings', {'key': key, 'value': value}, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  static Future<String?> getSetting(String key) async {
    final db = await database;
    final maps = await db.query('settings', where: 'key = ?', whereArgs: [key]);
    return maps.isNotEmpty ? maps.first['value'] as String : null;
  }

  static Future<bool> isCommandWhitelisted(String command) async {
    final db = await database;
    // Extract base command, skipping sudo/echo prefixes
    String baseCommand = command.trim();
    if (baseCommand.startsWith('echo ')) {
      baseCommand = baseCommand.substring(baseCommand.indexOf('|') + 1).trim();
    }
    if (baseCommand.startsWith('sudo ')) {
      baseCommand = baseCommand.substring(5).trim();
    }
    if (baseCommand.startsWith('-S ')) {
      baseCommand = baseCommand.substring(3).trim();
    }
    baseCommand = baseCommand.split(' ').first.toLowerCase();
    final maps = await db.query('command_whitelist', where: 'LOWER(command) = ?', whereArgs: [baseCommand]);
    return maps.isNotEmpty;
  }

  static Future<void> addToWhitelist(String command) async {
    final db = await database;
    // Extract base command, skipping sudo/echo prefixes
    String baseCommand = command.trim();
    if (baseCommand.startsWith('echo ')) {
      baseCommand = baseCommand.substring(baseCommand.indexOf('|') + 1).trim();
    }
    if (baseCommand.startsWith('sudo ')) {
      baseCommand = baseCommand.substring(5).trim();
    }
    if (baseCommand.startsWith('-S ')) {
      baseCommand = baseCommand.substring(3).trim();
    }
    baseCommand = baseCommand.split(' ').first.toLowerCase();
    await db.insert('command_whitelist', {
      'command': baseCommand,
      'added_at': DateTime.now().toIso8601String(),
    }, conflictAlgorithm: ConflictAlgorithm.ignore);
  }

  static Future<void> saveProviderSettings(String provider, Map<String, dynamic> settings) async {
    final db = await database;
    await db.insert('provider_settings', {
      'provider': provider,
      ...settings,
    }, conflictAlgorithm: ConflictAlgorithm.replace);
  }

  static Future<Map<String, dynamic>?> getProviderSettings(String provider) async {
    final db = await database;
    final maps = await db.query('provider_settings', where: 'provider = ?', whereArgs: [provider]);
    return maps.isNotEmpty ? maps.first : null;
  }

  // --- Projects ---

  static Future<int> insertProject(Project p) async {
    final db = await database;
    final map = Map<String, dynamic>.from(p.toMap())..remove('id');
    return await db.insert('projects', map);
  }

  static Future<List<Project>> getProjects() async {
    debugPrint('[DB] getProjects() called');
    final db = await database;
    debugPrint('[DB] getProjects() got database handle, querying projects table...');
    final maps = await db.query('projects', orderBy: 'lastOpenedAt DESC');
    debugPrint('[DB] getProjects() found ${maps.length} row(s): ${maps.map((m) => m['name']).toList()}');
    return maps.map((m) => Project.fromMap(m)).toList();
  }

  static Future<void> updateProjectLastOpened(int id) async {
    final db = await database;
    await db.update('projects', {'lastOpenedAt': DateTime.now().toIso8601String()}, where: 'id = ?', whereArgs: [id]);
  }

  static Future<void> updateProjectFlags(int id, {bool? scanComplete, bool? analysisComplete, bool? hasResults}) async {
    final db = await database;
    final updates = <String, dynamic>{};
    if (scanComplete != null) updates['scanComplete'] = scanComplete ? 1 : 0;
    if (analysisComplete != null) updates['analysisComplete'] = analysisComplete ? 1 : 0;
    if (hasResults != null) updates['hasResults'] = hasResults ? 1 : 0;
    if (updates.isNotEmpty) await db.update('projects', updates, where: 'id = ?', whereArgs: [id]);
  }

  static Future<void> deleteProject(int id) async {
    final db = await database;
    await db.delete('vulnerabilities', where: 'projectId = ?', whereArgs: [id]);
    await db.delete('command_logs', where: 'projectId = ?', whereArgs: [id]);
    await db.delete('prompt_logs', where: 'projectId = ?', whereArgs: [id]);
    await db.delete('debug_logs', where: 'projectId = ?', whereArgs: [id]);
    await db.delete('targets', where: 'projectId = ?', whereArgs: [id]);
    await db.delete('discovered_credentials', where: 'project_id = ?', whereArgs: [id]);
    await db.delete('projects', where: 'id = ?', whereArgs: [id]);
  }

  static Future<void> updateProjectReportFields(int projectId, {
    String? reportTitle,
    String? pentesterName,
    String? executiveSummary,
    String? methodology,
    String? riskRatingModel,
    String? conclusion,
  }) async {
    final db = await database;
    final updates = <String, dynamic>{};
    if (reportTitle != null) updates['report_title'] = reportTitle;
    if (pentesterName != null) updates['pentester_name'] = pentesterName;
    if (executiveSummary != null) updates['executive_summary'] = executiveSummary;
    if (methodology != null) updates['methodology'] = methodology;
    if (riskRatingModel != null) updates['risk_rating_model'] = riskRatingModel;
    if (conclusion != null) updates['conclusion'] = conclusion;
    if (updates.isNotEmpty) {
      await db.update('projects', updates, where: 'id = ?', whereArgs: [projectId]);
    }
  }

  static Future<void> updateProjectScope(int projectId, {
    String? scope,
    String? scopeExclusions,
    String? scopeNotes,
  }) async {
    final db = await database;
    // Use explicit null sentinel: pass empty string to clear, null to skip
    final updates = <String, dynamic>{
      'scope': scope,
      'scope_exclusions': scopeExclusions,
      'scope_notes': scopeNotes,
    };
    await db.update('projects', updates, where: 'id = ?', whereArgs: [projectId]);
  }

  static Future<void> updateProjectFirstAnalysis(int projectId, DateTime at) async {
    final db = await database;
    await db.update('projects', {'first_analysis_at': at.toIso8601String()},
        where: 'id = ?', whereArgs: [projectId]);
  }

  static Future<void> updateProjectLastExecution(int projectId, DateTime at) async {
    final db = await database;
    await db.update('projects', {'last_execution_at': at.toIso8601String()},
        where: 'id = ?', whereArgs: [projectId]);
  }

  // --- Discovered Credentials ---

  static Future<int> insertCredential(DiscoveredCredential cred, int projectId) async {
    final db = await database;
    return await db.insert(
      'discovered_credentials',
      {
        'project_id': projectId,
        'service': cred.service,
        'host': cred.host,
        'username': cred.username,
        'secret': cred.secret,
        'secret_type': cred.secretType,
        'source_vuln': cred.sourceVuln,
        'discovered_at': cred.discoveredAt.toIso8601String(),
      },
      conflictAlgorithm: ConflictAlgorithm.ignore,
    );
  }

  static Future<List<DiscoveredCredential>> getCredentialsByProject(int projectId) async {
    final db = await database;
    final maps = await db.query('discovered_credentials',
        where: 'project_id = ?', whereArgs: [projectId], orderBy: 'discovered_at ASC');
    return maps.map((m) => DiscoveredCredential.fromMap(m)).toList();
  }

  static Future<void> deleteCredentialsByProject(int projectId) async {
    final db = await database;
    await db.delete('discovered_credentials', where: 'project_id = ?', whereArgs: [projectId]);
  }

  // --- Targets ---

  static Future<int> insertTarget(int projectId, Target t) async {
    final db = await database;
    return await db.insert('targets', {
      'projectId': projectId,
      'address': t.address,
      'jsonFilePath': t.jsonFilePath,
      'summary': t.summary,
      'status': t.status.name,
      'analysisComplete': t.analysisComplete ? 1 : 0,
      'executionComplete': t.executionComplete ? 1 : 0,
    });
  }

  static Future<List<Target>> getTargets(int projectId) async {
    final db = await database;
    final maps = await db.query('targets', where: 'projectId = ?', whereArgs: [projectId]);
    return maps.map((m) => Target.fromMap(m)).toList();
  }

  static Future<void> updateTarget(Target t) async {
    final db = await database;
    await db.update('targets', t.toMap(), where: 'id = ?', whereArgs: [t.id]);
  }

  // --- Prompt logs ---

  static Future<int> insertPromptLog(int projectId, int targetId, String prompt, String response) async {
    final db = await database;
    return await db.insert('prompt_logs', {
      'projectId': projectId,
      'targetId': targetId,
      'prompt': prompt,
      'response': response,
      'timestamp': DateTime.now().toIso8601String(),
    });
  }

  static Future<List<Map<String, dynamic>>> getPromptLogs(int projectId, {int? targetId}) async {
    final db = await database;
    if (targetId != null) {
      return await db.query('prompt_logs', where: 'projectId = ? AND targetId = ?', whereArgs: [projectId, targetId], orderBy: 'timestamp ASC');
    }
    return await db.query('prompt_logs', where: 'projectId = ?', whereArgs: [projectId], orderBy: 'timestamp ASC');
  }

  static Future<void> clearPromptLogs(int projectId, {int? targetId}) async {
    final db = await database;
    if (targetId != null) {
      await db.delete('prompt_logs', where: 'projectId = ? AND targetId = ?', whereArgs: [projectId, targetId]);
    } else {
      await db.delete('prompt_logs', where: 'projectId = ?', whereArgs: [projectId]);
    }
  }

  // --- Debug logs ---

  static Future<int> insertDebugLog(int projectId, int targetId, String message) async {
    final db = await database;
    return await db.insert('debug_logs', {
      'projectId': projectId,
      'targetId': targetId,
      'message': message,
      'timestamp': DateTime.now().toIso8601String(),
    });
  }

  static Future<List<Map<String, dynamic>>> getDebugLogs(int projectId, {int? targetId}) async {
    final db = await database;
    if (targetId != null) {
      return await db.query('debug_logs', where: 'projectId = ? AND targetId = ?', whereArgs: [projectId, targetId], orderBy: 'timestamp ASC');
    }
    return await db.query('debug_logs', where: 'projectId = ?', whereArgs: [projectId], orderBy: 'timestamp ASC');
  }

  static Future<void> clearDebugLogs(int projectId, {int? targetId}) async {
    final db = await database;
    if (targetId != null) {
      await db.delete('debug_logs', where: 'projectId = ? AND targetId = ?', whereArgs: [projectId, targetId]);
    } else {
      await db.delete('debug_logs', where: 'projectId = ?', whereArgs: [projectId]);
    }
  }

  // --- Executed commands deduplication ---

  /// Normalize a command string for deduplication storage.
  static String _normalizeForStorage(String command) {
    return command
        .trim()
        .toLowerCase()
        .replaceAll(RegExp(r'\s+'), ' ')
        .replaceAll(RegExp(r'\d{4}-\d{2}-\d{2}'), 'DATE')
        .replaceAll(RegExp(r'\d{2}:\d{2}:\d{2}'), 'TIME');
  }

  /// Returns true if this exact (normalized) command has already been run
  /// for the given project+target combination.
  static Future<bool> wasCommandExecuted(int projectId, int targetId, String command) async {
    return (await getCachedCommandResult(projectId, targetId, command)) != null;
  }

  /// Record that a command was executed for a project+target, storing its output.
  /// On conflict (same normalized command), updates the output with the latest result.
  static Future<void> recordExecutedCommand(
    int projectId,
    int targetId,
    String command, {
    String output = '',
    int exitCode = -1,
  }) async {
    final db = await database;
    final normalized = _normalizeForStorage(command);
    // INSERT OR REPLACE so we always have the latest output stored
    await db.insert(
      'executed_commands',
      {
        'projectId': projectId,
        'targetId': targetId,
        'command_normalized': normalized,
        'output': output,
        'exit_code': exitCode,
        'executed_at': DateTime.now().toIso8601String(),
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Returns the cached output for a previously executed command, or null if
  /// the command has never been run for this project+target.
  static Future<({String output, int exitCode})?> getCachedCommandResult(
    int projectId,
    int targetId,
    String command,
  ) async {
    final db = await database;
    final normalized = _normalizeForStorage(command);
    final rows = await db.query(
      'executed_commands',
      columns: ['output', 'exit_code'],
      where: 'projectId = ? AND targetId = ? AND command_normalized = ?',
      whereArgs: [projectId, targetId, normalized],
      limit: 1,
    );
    if (rows.isEmpty) return null;
    return (
      output: rows.first['output'] as String? ?? '',
      exitCode: rows.first['exit_code'] as int? ?? -1,
    );
  }

  /// Load all previously executed command normalized strings for a project+target.
  /// Used to pre-populate the in-memory dedup set at the start of a run.
  static Future<Set<String>> getExecutedCommands(int projectId, int targetId) async {
    final db = await database;
    final rows = await db.query(
      'executed_commands',
      columns: ['command_normalized'],
      where: 'projectId = ? AND targetId = ?',
      whereArgs: [projectId, targetId],
    );
    return rows.map((r) => r['command_normalized'] as String).toSet();
  }

  /// Clear executed commands for a target (e.g. when re-running recon).
  static Future<void> clearExecutedCommands(int projectId, int targetId) async {
    final db = await database;
    await db.delete(
      'executed_commands',
      where: 'projectId = ? AND targetId = ?',
      whereArgs: [projectId, targetId],
    );
  }
}
