import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Manages long-running background processes (listeners) for attacks that
/// require a persistent listener + optional trigger pattern:
///   - LLMNR/NBT-NS poisoning (Responder)
///   - NTLM relay (ntlmrelayx)
///   - DHCPv6/IPv6 attacks (mitm6)
///   - WPAD rogue server
///
/// Each process is identified by a [name] and accumulates stdout/stderr into
/// a rolling buffer that the executor can read at any time.
class BackgroundProcessManager {
  static final BackgroundProcessManager _instance =
      BackgroundProcessManager._internal();
  factory BackgroundProcessManager() => _instance;
  BackgroundProcessManager._internal();

  final Map<String, _ManagedProcess> _processes = {};

  /// Start a background process by [name]. If a process with this name is
  /// already running it is returned without restarting.
  Future<void> start(String name, String command, {
    String? workingDirectory,
    int maxBufferLines = 500,
  }) async {
    if (_processes.containsKey(name) && (_processes[name]!.isAlive)) return;

    final parts = _splitCommand(command);
    if (parts.isEmpty) return;

    final process = await Process.start(
      parts.first,
      parts.sublist(1),
      workingDirectory: workingDirectory,
      runInShell: Platform.isWindows,
    );

    final managed = _ManagedProcess(
      name: name,
      process: process,
      maxBufferLines: maxBufferLines,
    );
    _processes[name] = managed;

    // Accumulate stdout
    process.stdout
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) => managed._appendLine(line));
    // Accumulate stderr (many pentest tools write interesting output to stderr)
    process.stderr
        .transform(utf8.decoder)
        .transform(const LineSplitter())
        .listen((line) => managed._appendLine('[err] $line'));
  }

  /// Stop the process identified by [name] and remove it.
  Future<void> stop(String name) async {
    final p = _processes.remove(name);
    if (p == null) return;
    try {
      p.process.kill(ProcessSignal.sigterm);
      await p.process.exitCode.timeout(const Duration(seconds: 5));
    } catch (_) {
      try { p.process.kill(ProcessSignal.sigkill); } catch (_) {}
    }
  }

  /// Stop all running background processes. Called on app shutdown.
  Future<void> stopAll() async {
    for (final name in _processes.keys.toList()) {
      await stop(name);
    }
  }

  /// Returns true if a process named [name] is still alive.
  bool isAlive(String name) => _processes[name]?.isAlive ?? false;

  /// Returns all accumulated output lines for [name] since it started.
  List<String> getOutput(String name) =>
      List.unmodifiable(_processes[name]?._buffer ?? []);

  /// Returns new output lines since [lastSeenIndex] for [name].
  List<String> getOutputSince(String name, int lastSeenIndex) {
    final buf = _processes[name]?._buffer ?? [];
    if (lastSeenIndex >= buf.length) return [];
    return List.unmodifiable(buf.sublist(lastSeenIndex));
  }

  /// Current output buffer length for [name] — use as a cursor.
  int outputLength(String name) => _processes[name]?._buffer.length ?? 0;

  /// Returns a snapshot of all output joined into a single string.
  String getOutputString(String name) =>
      (_processes[name]?._buffer ?? []).join('\n');

  /// All currently running process names.
  List<String> get activeNames =>
      _processes.entries.where((e) => e.value.isAlive).map((e) => e.key).toList();

  // ---------------------------------------------------------------------------
  // Listener tool detection — classify a command as requiring background mode
  // ---------------------------------------------------------------------------

  /// Well-known listener tools that must run as background processes.
  static const _listenerTools = {
    'responder', 'ntlmrelayx', 'mitm6', 'impacket-ntlmrelayx',
    'impacket-smbserver', 'smbserver', 'bettercap', 'ettercap',
    'mitmproxy', 'dnschef', 'fakedns', 'evilginx',
  };

  /// Returns true if [command] contains a known listener tool that should be
  /// run as a background process rather than blocking.
  static bool isListenerCommand(String command) {
    final lower = command.toLowerCase();
    return _listenerTools.any((t) => lower.contains(t));
  }

  // ---------------------------------------------------------------------------
  // Helpers
  // ---------------------------------------------------------------------------

  static List<String> _splitCommand(String command) {
    // Simple split respecting single/double quotes
    final result = <String>[];
    final current = StringBuffer();
    String? quote;
    for (var i = 0; i < command.length; i++) {
      final ch = command[i];
      if (quote != null) {
        if (ch == quote) {
          quote = null;
        } else {
          current.write(ch);
        }
      } else if (ch == '"' || ch == "'") {
        quote = ch;
      } else if (ch == ' ') {
        if (current.isNotEmpty) {
          result.add(current.toString());
          current.clear();
        }
      } else {
        current.write(ch);
      }
    }
    if (current.isNotEmpty) result.add(current.toString());
    return result;
  }
}

class _ManagedProcess {
  final String name;
  final Process process;
  final int maxBufferLines;
  final List<String> _buffer = [];

  _ManagedProcess({
    required this.name,
    required this.process,
    required this.maxBufferLines,
  });

  void _appendLine(String line) {
    _buffer.add(line);
    if (_buffer.length > maxBufferLines) {
      _buffer.removeAt(0);
    }
  }

  bool get isAlive {
    try {
      // kill(0) checks existence without actually signalling on POSIX.
      // On Dart we can only check if the exitCode future has completed.
      return !process.exitCode.isCompleted;
    } catch (_) {
      return false;
    }
  }
}

extension _FutureCompleted<T> on Future<T> {
  bool get isCompleted {
    var done = false;
    then((_) => done = true).ignore();
    return done;
  }
}
