import 'dart:io';
import 'package:path/path.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';
import '../models/vulnerability.dart';
import '../models/command_log.dart';

class DatabaseHelper {
  static Database? _database;

  static Future<void> initialize() async {
    if (Platform.isWindows || Platform.isLinux) {
      sqfliteFfiInit();
      databaseFactory = databaseFactoryFfi;
    }
  }

  static Future<Database> get database async {
    if (_database != null) return _database!;
    _database = await _initDatabase();
    return _database!;
  }

  static Future<Database> _initDatabase() async {
    final dbPath = await getDatabasesPath();
    final path = join(dbPath, 'penexecute.db');
    
    return await openDatabase(
      path,
      version: 4,
      onCreate: (db, version) async {
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
            statusReason TEXT,
            proofCommand TEXT,
            status TEXT NOT NULL
          )
        ''');

        await db.execute('''
          CREATE TABLE command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            command TEXT NOT NULL,
            output TEXT NOT NULL,
            exitCode INTEGER NOT NULL,
            vulnerabilityIndex INTEGER
          )
        ''');

        await db.execute('''
          CREATE TABLE settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
          )
        ''');
      },
      onUpgrade: (db, oldVersion, newVersion) async {
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
      },
    );
  }

  static Future<int> insertVulnerability(Vulnerability vuln) async {
    final db = await database;
    return await db.insert('vulnerabilities', vuln.toMap());
  }

  static Future<List<Vulnerability>> getVulnerabilities() async {
    final db = await database;
    final maps = await db.query('vulnerabilities');
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

  static Future<List<CommandLog>> getCommandLogs() async {
    final db = await database;
    final maps = await db.query('command_logs', orderBy: 'timestamp DESC');
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
}
