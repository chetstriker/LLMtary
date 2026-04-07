import 'dart:io';
import 'package:dbus/dbus.dart';
import 'package:file_picker/file_picker.dart';

/// File dialog wrapper.
/// Linux priority: xdg-desktop-portal → kdialog → zenity → ~/Downloads fallback
/// macOS/Windows: file_picker (native)
class FileDialog {
  static Future<String?> saveFile({
    required String fileName,
    String dialogTitle = 'Save File',
  }) async {
    if (Platform.isLinux) {
      return await _portalSaveFile(fileName, dialogTitle) ??
          await _legacySaveFile(fileName, dialogTitle);
    }
    return FilePicker.saveFile(dialogTitle: dialogTitle, fileName: fileName);
  }

  static Future<String?> getDirectoryPath({String dialogTitle = 'Select Folder'}) async {
    if (Platform.isLinux) {
      // Portal doesn't support directory picking; go straight to legacy tools
      return await _legacyDirDialog(dialogTitle);
    }
    return FilePicker.getDirectoryPath(dialogTitle: dialogTitle);
  }

  static Future<FilePickerResult?> pickFiles({
    String dialogTitle = 'Open File',
    List<String>? allowedExtensions,
  }) async {
    if (Platform.isLinux) {
      final path = await _portalOpenFile(dialogTitle, allowedExtensions) ??
          await _legacyOpenFile(dialogTitle, allowedExtensions);
      if (path == null) return null;
      return FilePickerResult([PlatformFile(path: path, name: path.split('/').last, size: 0)]);
    }
    return FilePicker.pickFiles(
      dialogTitle: dialogTitle,
      type: allowedExtensions != null ? FileType.custom : FileType.any,
      allowedExtensions: allowedExtensions,
    );
  }

  // ── xdg-desktop-portal ────────────────────────────────────────────────────

  static Future<String?> _portalSaveFile(String fileName, String title) async {
    DBusClient? client;
    try {
      client = DBusClient.session();
      final handle = await _callPortal(client, 'SaveFile', title, {
        'current_name': DBusString(fileName),
        'current_folder': _pathToBytes('${Platform.environment['HOME'] ?? '/tmp'}/Downloads'),
      });
      if (handle == null) return null;
      final uris = await _waitForResponse(client, handle);
      return uris?.firstOrNull?.replaceFirst('file://', '');
    } catch (_) {
      return null;
    } finally {
      await client?.close();
    }
  }

  static Future<String?> _portalOpenFile(String title, List<String>? extensions) async {
    DBusClient? client;
    try {
      client = DBusClient.session();
      final filters = extensions != null ? _buildFilters(extensions) : null;
      final options = <String, DBusValue>{};
      if (filters != null) options['filters'] = filters;
      final handle = await _callPortal(client, 'OpenFile', title, options);
      if (handle == null) return null;
      final uris = await _waitForResponse(client, handle);
      return uris?.firstOrNull?.replaceFirst('file://', '');
    } catch (_) {
      return null;
    } finally {
      await client?.close();
    }
  }

  static Future<DBusObjectPath?> _callPortal(
    DBusClient client,
    String method,
    String title,
    Map<String, DBusValue> options,
  ) async {
    try {
      final result = await client.callMethod(
        destination: 'org.freedesktop.portal.Desktop',
        path: DBusObjectPath('/org/freedesktop/portal/desktop'),
        interface: 'org.freedesktop.portal.FileChooser',
        name: method,
        values: [
          const DBusString(''), // parent window handle
          DBusString(title),
          DBusDict(
            DBusSignature('s'),
            DBusSignature('v'),
            options.map((k, v) => MapEntry(DBusString(k), DBusVariant(v))),
          ),
        ],
      );
      return result.values.first as DBusObjectPath;
    } catch (_) {
      return null;
    }
  }

  /// Subscribes to the Response signal on [handle] and returns the URIs list.
  static Future<List<String>?> _waitForResponse(DBusClient client, DBusObjectPath handle) async {
    final stream = DBusSignalStream(
      client,
      sender: 'org.freedesktop.portal.Desktop',
      interface: 'org.freedesktop.portal.Request',
      name: 'Response',
      path: handle,
    );
    await for (final signal in stream) {
      if (true) {
        final response = signal.values[0] as DBusUint32;
        if (response.value != 0) return null; // cancelled or error
        final results = (signal.values[1] as DBusDict).children;
        final urisEntry = results[const DBusString('uris')];
        if (urisEntry == null) return null;
        final urisVariant = urisEntry as DBusVariant;
        final urisArray = urisVariant.value as DBusArray;
        return urisArray.children.map((v) => (v as DBusString).value).toList();
      }
    }
    return null;
  }

  static DBusArray _buildFilters(List<String> extensions) {
    // filters: a(sa(us)) — array of (name, array of (type, pattern))
    // type 0 = glob pattern
    final patterns = extensions
        .map((e) => DBusStruct([const DBusUint32(0), DBusString('*.$e')]))
        .toList();
    return DBusArray(
      DBusSignature('(sa(us))'),
      [
        DBusStruct([
          DBusString(extensions.join(', ')),
          DBusArray(DBusSignature('(us)'), patterns),
        ])
      ],
    );
  }

  static DBusArray _pathToBytes(String path) {
    final bytes = [...path.codeUnits.map((b) => DBusByte(b)), DBusByte(0)];
    return DBusArray(DBusSignature('y'), bytes);
  }

  // ── Legacy fallback (kdialog / zenity) ────────────────────────────────────

  static String? _cachedTool;

  static Future<String?> _legacyTool() async {
    if (_cachedTool != null) return _cachedTool!.isEmpty ? null : _cachedTool;
    for (final t in ['kdialog', 'zenity']) {
      if ((await Process.run('which', [t])).exitCode == 0) {
        return _cachedTool = t;
      }
    }
    _cachedTool = '';
    return null;
  }

  static Future<String?> _legacySaveFile(String fileName, String title) async {
    final tool = await _legacyTool();
    if (tool == null) return _fallbackSavePath(fileName);
    final home = Platform.environment['HOME'] ?? '/tmp';
    final defaultPath = '$home/Downloads/$fileName';
    try {
      final r = tool == 'kdialog'
          ? await Process.run('kdialog', ['--title', title, '--getsavefilename', defaultPath])
          : await Process.run('zenity', [
              '--file-selection', '--save', '--confirm-overwrite',
              '--title=$title', '--filename=$defaultPath',
            ]);
      final path = r.stdout.toString().trim();
      return (r.exitCode == 0 && path.isNotEmpty) ? path : null;
    } catch (_) {
      return _fallbackSavePath(fileName);
    }
  }

  static Future<String?> _legacyDirDialog(String title) async {
    final tool = await _legacyTool();
    if (tool == null) return null;
    try {
      final r = tool == 'kdialog'
          ? await Process.run('kdialog', ['--title', title, '--getexistingdirectory', Platform.environment['HOME'] ?? '/'])
          : await Process.run('zenity', ['--file-selection', '--directory', '--title=$title']);
      final path = r.stdout.toString().trim();
      return (r.exitCode == 0 && path.isNotEmpty) ? path : null;
    } catch (_) {
      return null;
    }
  }

  static Future<String?> _legacyOpenFile(String title, List<String>? extensions) async {
    final tool = await _legacyTool();
    if (tool == null) return null;
    try {
      final r = tool == 'kdialog'
          ? await Process.run('kdialog', [
              '--title', title,
              '--getopenfilename', Platform.environment['HOME'] ?? '/',
              if (extensions != null) extensions.map((e) => '*.$e').join(' '),
            ])
          : await Process.run('zenity', ['--file-selection', '--title=$title']);
      final path = r.stdout.toString().trim();
      return (r.exitCode == 0 && path.isNotEmpty) ? path : null;
    } catch (_) {
      return null;
    }
  }

  static Future<String> _fallbackSavePath(String fileName) async {
    final dir = Directory('${Platform.environment['HOME'] ?? '/tmp'}/Downloads');
    if (!await dir.exists()) await dir.create(recursive: true);
    return '${dir.path}/$fileName';
  }
}
