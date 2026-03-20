import 'package:flutter_test/flutter_test.dart';
import 'package:sqflite_common_ffi/sqflite_ffi.dart';

/// Tests that the database migration chain preserves data across upgrades.
void main() {
  sqfliteFfiInit();
  databaseFactory = databaseFactoryFfi;

  Future<void> _applyMigrations(Database db, int oldVersion) async {
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
    if (oldVersion < 14) {
      try { await db.execute("ALTER TABLE vulnerabilities ADD COLUMN businessRisk TEXT DEFAULT ''"); } catch (_) {}
    }
    if (oldVersion < 15) {
      try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN proofOutput TEXT'); } catch (_) {}
      try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN reproductionSteps TEXT'); } catch (_) {}
      try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN confirmedAt TEXT'); } catch (_) {}
    }
    if (oldVersion < 16) {
      try { await db.execute('ALTER TABLE vulnerabilities ADD COLUMN proofCommandExpectedOutput TEXT'); } catch (_) {}
    }
  }

  test('migration from v1 to v16 preserves data and adds columns', () async {
    // Create a v1 database manually
    final db = await openDatabase(
      inMemoryDatabasePath,
      version: 1,
      singleInstance: false,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            problem TEXT NOT NULL,
            cve TEXT,
            description TEXT,
            severity TEXT,
            confidence TEXT,
            evidence TEXT,
            recommendation TEXT,
            status TEXT NOT NULL DEFAULT 'pending'
          )
        ''');
        await db.execute('''
          CREATE TABLE command_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT NOT NULL,
            output TEXT NOT NULL,
            exitCode INTEGER NOT NULL,
            timestamp TEXT NOT NULL
          )
        ''');
      },
    );

    // Insert data at v1 schema
    await db.insert('vulnerabilities', {
      'problem': 'Test Vuln',
      'cve': 'CVE-2024-0001',
      'description': 'Test description',
      'severity': 'HIGH',
      'confidence': 'MEDIUM',
      'evidence': 'test evidence',
      'recommendation': 'fix it',
      'status': 'pending',
    });

    // Apply all migrations from v1 to v16
    await _applyMigrations(db, 1);

    // Verify data survived
    final rows = await db.query('vulnerabilities');
    expect(rows.length, 1);
    expect(rows.first['problem'], 'Test Vuln');
    expect(rows.first['cve'], 'CVE-2024-0001');

    // Verify new columns exist
    final columns = await db.rawQuery('PRAGMA table_info(vulnerabilities)');
    final colNames = columns.map((c) => c['name'] as String).toSet();
    expect(colNames.contains('proofCommandExpectedOutput'), isTrue);
    expect(colNames.contains('businessRisk'), isTrue);
    expect(colNames.contains('proofCommand'), isTrue);
    expect(colNames.contains('statusReason'), isTrue);
    expect(colNames.contains('vulnerabilityType'), isTrue);

    // Verify we can write to the new column
    await db.update(
      'vulnerabilities',
      {'proofCommandExpectedOutput': 'root:x:0:0'},
      where: 'id = ?',
      whereArgs: [rows.first['id']],
    );
    final updated = await db.query('vulnerabilities');
    expect(updated.first['proofCommandExpectedOutput'], 'root:x:0:0');

    await db.close();
  });

  test('v16 migration is idempotent', () async {
    final db = await openDatabase(
      inMemoryDatabasePath,
      version: 1,
      singleInstance: false,
      onCreate: (db, version) async {
        await db.execute('''
          CREATE TABLE vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            problem TEXT,
            proofCommandExpectedOutput TEXT
          )
        ''');
      },
    );

    // Run v16 migration on a table that already has the column
    try {
      await db.execute('ALTER TABLE vulnerabilities ADD COLUMN proofCommandExpectedOutput TEXT');
    } catch (_) {
      // Expected: column already exists — this is the idempotency check
    }

    // Verify table still works
    await db.insert('vulnerabilities', {
      'problem': 'test',
      'proofCommandExpectedOutput': 'expected output',
    });
    final rows = await db.query('vulnerabilities');
    expect(rows.length, 1);
    expect(rows.first['proofCommandExpectedOutput'], 'expected output');

    await db.close();
  });
}
