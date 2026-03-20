import 'dart:io';
import 'command_executor.dart';

/// A discovered host from a subnet sweep.
class DiscoveredHost {
  final String ip;
  final List<int> openPorts;
  final String os;
  final String hostname;

  const DiscoveredHost({
    required this.ip,
    this.openPorts = const [],
    this.os = '',
    this.hostname = '',
  });

  /// Priority score for triage — higher is more interesting.
  int get priorityScore {
    int score = 0;
    // High-value ports
    const highValue = {445, 389, 88, 443, 3389, 5985, 1433, 3306, 5432, 27017, 6379, 9200, 2375};
    for (final p in openPorts) {
      if (highValue.contains(p)) { score += 10; } else { score += 1; }
    }
    // DC-like hostnames
    final h = hostname.toLowerCase();
    if (h.contains('dc') || h.contains('domain') || h.contains('ad')) score += 20;
    // More open ports = more interesting
    score += openPorts.length;
    return score;
  }

  /// Build a minimal device JSON stub for feeding into VulnerabilityAnalyzer.
  String toDeviceJson() {
    final ports = openPorts.map((p) => '{"port": $p, "service": ""}').join(', ');
    return '{"ip": "$ip", "hostname": "$hostname", "os": "$os", "open_ports": [$ports]}';
  }
}

/// Performs ping sweeps and fast port scans over a CIDR range to enumerate
/// live hosts and their open ports.
///
/// Usage:
/// ```dart
/// final hosts = await SubnetScanner.scan('192.168.1.0/24',
///   onProgress: (msg) => print(msg));
/// ```
class SubnetScanner {
  /// Validate that [input] is a CIDR notation string (e.g. "192.168.1.0/24").
  static bool isCidr(String input) {
    final trimmed = input.trim();
    final cidrRe = RegExp(
      r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$',
    );
    return cidrRe.hasMatch(trimmed);
  }

  /// Expand a /24 CIDR to the list of host IPs (up to /16 supported).
  /// Returns null for unsupported prefix lengths.
  static List<String>? expandCidr(String cidr) {
    final parts = cidr.trim().split('/');
    if (parts.length != 2) return null;
    final prefix = int.tryParse(parts[1]) ?? -1;
    if (prefix < 16 || prefix > 30) return null; // safety cap
    final octets = parts[0].split('.').map(int.parse).toList();
    if (octets.length != 4) return null;

    final hostBits = 32 - prefix;
    final hostCount = (1 << hostBits) - 2; // exclude network and broadcast
    if (hostCount > 65534) return null;

    final networkInt = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
    final hosts = <String>[];
    for (var i = 1; i <= hostCount; i++) {
      final addr = networkInt + i;
      hosts.add('${(addr >> 24) & 0xFF}.${(addr >> 16) & 0xFF}.${(addr >> 8) & 0xFF}.${addr & 0xFF}');
    }
    return hosts;
  }

  /// Scan a CIDR range. Returns discovered hosts sorted by priority (highest first).
  ///
  /// Uses nmap for efficiency when available; falls back to individual pings.
  static Future<List<DiscoveredHost>> scan(
    String cidr, {
    void Function(String)? onProgress,
    Duration timeout = const Duration(minutes: 5),
  }) async {
    onProgress?.call('Starting subnet scan: $cidr');

    // Try nmap first (fastest)
    final nmapResult = await _nmapScan(cidr, onProgress: onProgress)
        .timeout(timeout, onTimeout: () => []);
    if (nmapResult.isNotEmpty) return nmapResult;

    // Fallback: expand CIDR and ping-sweep
    onProgress?.call('nmap unavailable — falling back to ping sweep');
    final hosts = expandCidr(cidr);
    if (hosts == null) {
      onProgress?.call('Unsupported CIDR range (only /16–/30 supported)');
      return [];
    }
    return _pingSweep(hosts, onProgress: onProgress)
        .timeout(timeout, onTimeout: () => []);
  }

  // ---------------------------------------------------------------------------
  // nmap-based scan
  // ---------------------------------------------------------------------------

  static Future<List<DiscoveredHost>> _nmapScan(
    String cidr, {
    void Function(String)? onProgress,
  }) async {
    // Fast host discovery + common port scan
    // -sn: ping sweep only first, then -p for top ports on live hosts
    onProgress?.call('Running nmap ping sweep on $cidr...');
    final sweepResult = await CommandExecutor.executeCommand(
      'nmap -sn --open -T4 $cidr -oG -',
      false,
    ).timeout(const Duration(minutes: 3), onTimeout: () => {'output': '', 'exitCode': -1});

    final sweepOutput = (sweepResult['output'] ?? '').toString();
    if ((sweepResult['exitCode'] ?? -1) != 0 || sweepOutput.isEmpty) return [];

    // Extract live IPs from grepable output: "Host: 192.168.1.1 () Status: Up"
    final liveIps = RegExp(r'Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s')
        .allMatches(sweepOutput)
        .map((m) => m.group(1)!)
        .toList();

    if (liveIps.isEmpty) return [];
    onProgress?.call('Found ${liveIps.length} live hosts — scanning ports...');

    // Port scan the live hosts
    final targetList = liveIps.join(' ');
    final portResult = await CommandExecutor.executeCommand(
      'nmap -p 21,22,23,25,53,80,88,110,111,135,139,143,389,443,445,636,'
      '1433,1521,2375,2376,3000,3306,3389,5432,5985,5986,6379,8080,8443,'
      '9200,27017 --open -T4 -oG - $targetList',
      false,
    ).timeout(const Duration(minutes: 3), onTimeout: () => {'output': '', 'exitCode': -1});

    final portOutput = (portResult['output'] ?? '').toString();
    return _parseNmapGrepable(portOutput, liveIps);
  }

  static List<DiscoveredHost> _parseNmapGrepable(String output, List<String> liveIps) {
    final hostMap = <String, DiscoveredHost>{};
    for (final line in output.split('\n')) {
      if (!line.startsWith('Host:')) continue;
      final ipMatch = RegExp(r'Host:\s+(\d{1,3}(?:\.\d{1,3}){3})\s+\(([^)]*)\)').firstMatch(line);
      if (ipMatch == null) continue;
      final ip = ipMatch.group(1)!;
      final hostname = ipMatch.group(2) ?? '';
      final ports = <int>[];
      for (final pm in RegExp(r'(\d+)/open').allMatches(line)) {
        final port = int.tryParse(pm.group(1) ?? '');
        if (port != null) ports.add(port);
      }
      hostMap[ip] = DiscoveredHost(ip: ip, openPorts: ports, hostname: hostname);
    }
    // Include live hosts with no open ports (still interesting for ping-only targets)
    for (final ip in liveIps) {
      hostMap.putIfAbsent(ip, () => DiscoveredHost(ip: ip));
    }
    final sorted = hostMap.values.toList()
      ..sort((a, b) => b.priorityScore.compareTo(a.priorityScore));
    return sorted;
  }

  // ---------------------------------------------------------------------------
  // Fallback ping sweep
  // ---------------------------------------------------------------------------

  static Future<List<DiscoveredHost>> _pingSweep(
    List<String> ips, {
    void Function(String)? onProgress,
  }) async {
    onProgress?.call('Ping sweeping ${ips.length} addresses...');
    final liveHosts = <DiscoveredHost>[];
    // Batch pings in groups of 20 concurrent
    for (var i = 0; i < ips.length; i += 20) {
      final batch = ips.skip(i).take(20);
      final results = await Future.wait(batch.map((ip) => _pingHost(ip)));
      liveHosts.addAll(results.whereType<DiscoveredHost>());
    }
    liveHosts.sort((a, b) => b.priorityScore.compareTo(a.priorityScore));
    return liveHosts;
  }

  static Future<DiscoveredHost?> _pingHost(String ip) async {
    try {
      final cmd = Platform.isWindows ? 'ping -n 1 -w 500 $ip' : 'ping -c 1 -W 1 $ip';
      final result = await CommandExecutor.executeCommand(cmd, false)
          .timeout(const Duration(seconds: 3), onTimeout: () => {'exitCode': -1});
      if ((result['exitCode'] ?? -1) == 0) {
        return DiscoveredHost(ip: ip);
      }
    } catch (_) {}
    return null;
  }
}
