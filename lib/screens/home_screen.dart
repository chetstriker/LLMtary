import 'package:flutter/material.dart';
import 'package:provider/provider.dart';
import '../database/database_helper.dart';
import '../models/project.dart';
import '../services/project_porter.dart';
import '../services/storage_service.dart';
import '../widgets/app_state.dart';
import '../widgets/llm_setup_wizard.dart';
import 'main_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> {
  List<Project> _projects = [];
  bool _loading = true;
  final Map<int, int> _projectTokenTotals = {};

  static const _cyan = Color(0xFF7C5CFC);
  static const _bg = Color(0xFF0D0F1A);
  static const _card = Color(0xFF161929);

  @override
  void initState() {
    super.initState();
    _loadProjects();
    WidgetsBinding.instance.addPostFrameCallback((_) => _checkWizard());
  }

  Future<void> _checkWizard() async {
    final provider = await DatabaseHelper.getSetting('current_provider');
    final isConfigured = provider != null && provider != 'none' && provider.isNotEmpty;
    if (!isConfigured && mounted) {
      showDialog(
        context: context,
        barrierDismissible: false,
        builder: (_) => const LlmSetupWizard(),
      );
    }
  }

  Future<void> _loadProjects() async {
    debugPrint('[HomeScreen] _loadProjects() started, mounted=$mounted');
    setState(() => _loading = true);
    try {
      debugPrint('[HomeScreen] calling DatabaseHelper.getProjects()...');
      _projects = await DatabaseHelper.getProjects();
      debugPrint('[HomeScreen] getProjects() returned ${_projects.length} project(s): ${_projects.map((p) => p.name).toList()}');
      // Load token totals for each project
      for (final p in _projects) {
        if (p.id != null) {
          final totals = await DatabaseHelper.getTokenTotals(p.id!);
          _projectTokenTotals[p.id!] = (totals['totalSent'] ?? 0) + (totals['totalReceived'] ?? 0);
        }
      }
    } catch (e, st) {
      debugPrint('[HomeScreen] getProjects() threw: $e\n$st');
    } finally {
      debugPrint('[HomeScreen] finally block, mounted=$mounted');
      if (mounted) {
        setState(() => _loading = false);
        debugPrint('[HomeScreen] _loading set to false');
      } else {
        debugPrint('[HomeScreen] widget not mounted, _loading NOT cleared');
      }
    }
  }

  Future<void> _createProject() async {
    final nameController = TextEditingController();
    final name = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _card,
        title: const Text('New Project', style: TextStyle(color: _cyan)),
        content: TextField(
          controller: nameController,
          autofocus: true,
          style: const TextStyle(color: Colors.white),
          decoration: InputDecoration(
            hintText: 'Project name',
            hintStyle: const TextStyle(color: Colors.white38),
            enabledBorder: OutlineInputBorder(borderSide: BorderSide(color: _cyan.withValues(alpha: 0.4))),
            focusedBorder: const OutlineInputBorder(borderSide: BorderSide(color: _cyan)),
          ),
          onSubmitted: (v) => Navigator.of(ctx).pop(v.trim()),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: const Text('CANCEL', style: TextStyle(color: Colors.white54))),
          TextButton(onPressed: () => Navigator.of(ctx).pop(nameController.text.trim()), child: const Text('CREATE', style: TextStyle(color: _cyan))),
        ],
      ),
    );

    if (name == null || name.isEmpty) return;

    // Validate name
    if (RegExp(r'[/\\:*?"<>|]').hasMatch(name)) {
      _showSnack('Invalid characters in project name');
      return;
    }
    if (_projects.any((p) => p.name.toLowerCase() == name.toLowerCase())) {
      _showSnack('A project with that name already exists');
      return;
    }

    final folderPath = await StorageService.getProjectPath(name);
    final now = DateTime.now();
    final project = Project(
      name: name,
      folderPath: folderPath,
      createdAt: now,
      lastOpenedAt: now,
    );
    final id = await DatabaseHelper.insertProject(project);
    final created = Project(
      id: id,
      name: project.name,
      folderPath: project.folderPath,
      createdAt: project.createdAt,
      lastOpenedAt: project.lastOpenedAt,
    );
    await _openProject(created);
  }

  Future<void> _openProject(Project project) async {
    await DatabaseHelper.updateProjectLastOpened(project.id!);
    if (!mounted) return;
    final appState = context.read<AppState>();
    await appState.setCurrentProject(project);
    if (!mounted) return;
    Navigator.of(context).push(MaterialPageRoute(builder: (_) => const MainScreen()));
    _loadProjects();
  }

  Future<void> _deleteProject(Project project) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _card,
        title: const Text('Delete Project', style: TextStyle(color: Color(0xFFFF0040))),
        content: Text("Delete '${project.name}'? This will permanently remove all scan data.", style: const TextStyle(color: Colors.white70)),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(false), child: const Text('CANCEL', style: TextStyle(color: Colors.white54))),
          TextButton(onPressed: () => Navigator.of(ctx).pop(true), child: const Text('DELETE', style: TextStyle(color: Color(0xFFFF0040)))),
        ],
      ),
    );
    if (confirmed != true) return;
    await StorageService.deleteProjectFolder(project.name);
    await DatabaseHelper.deleteProject(project.id!);
    _loadProjects();
  }

  Future<void> _importProject() async {
    final project = await ProjectPorter.importProject(context);
    if (project != null && mounted) {
      await _openProject(project);
    }
  }

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _bg,
      body: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 860),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 40, vertical: 40),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        gradient: const LinearGradient(colors: [_cyan, Color(0xFF0080FF)]),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: const Icon(Icons.security, color: Colors.white, size: 32),
                    ),
                    const SizedBox(width: 16),
                    const Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text('LLMtary', style: TextStyle(color: Colors.white, fontSize: 28, fontFamily: 'BungeeSpice')),
                        Text('Automated Penetration Testing', style: TextStyle(color: Colors.white38, fontSize: 13)),
                      ],
                    ),
                  ],
                ),
                const SizedBox(height: 40),
                Row(
                  children: [
                    ElevatedButton.icon(
                      onPressed: _createProject,
                      icon: const Icon(Icons.add, color: Colors.white),
                      label: const Text('NEW PROJECT', style: TextStyle(color: Colors.white, fontWeight: FontWeight.bold, letterSpacing: 1)),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: _cyan,
                        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
                      ),
                    ),
                    const SizedBox(width: 12),
                    OutlinedButton.icon(
                      onPressed: _importProject,
                      icon: const Icon(Icons.upload, color: _cyan, size: 18),
                      label: const Text('IMPORT', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, letterSpacing: 1)),
                      style: OutlinedButton.styleFrom(
                        side: const BorderSide(color: _cyan),
                        padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 32),
                const Text('RECENT PROJECTS', style: TextStyle(color: _cyan, fontWeight: FontWeight.bold, fontSize: 11, letterSpacing: 1.5)),
                const SizedBox(height: 12),
                Expanded(
                  child: _loading
                      ? const Center(child: CircularProgressIndicator(color: _cyan))
                      : _projects.isEmpty
                          ? Center(
                              child: Column(
                                mainAxisAlignment: MainAxisAlignment.center,
                                children: [
                                  Icon(Icons.folder_open, size: 64, color: Colors.white.withValues(alpha: 0.1)),
                                  const SizedBox(height: 16),
                                  Text('No projects yet', style: TextStyle(color: Colors.white.withValues(alpha: 0.3), fontSize: 16)),
                                  const SizedBox(height: 8),
                                  Text('Create a new project to get started', style: TextStyle(color: Colors.white.withValues(alpha: 0.2), fontSize: 12)),
                                ],
                              ),
                            )
                          : ListView.builder(
                              itemCount: _projects.length,
                              itemBuilder: (ctx, i) => _buildProjectRow(_projects[i]),
                            ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildProjectRow(Project project) {
    final lastOpened = project.lastOpenedAt;
    final dateStr = '${lastOpened.year}-${lastOpened.month.toString().padLeft(2, '0')}-${lastOpened.day.toString().padLeft(2, '0')}';
    final tokens = project.id != null ? (_projectTokenTotals[project.id!] ?? 0) : 0;

    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      decoration: BoxDecoration(
        color: _card,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: _cyan.withValues(alpha: 0.12)),
      ),
      child: InkWell(
        borderRadius: BorderRadius.circular(8),
        onTap: () => _openProject(project),
        hoverColor: _cyan.withValues(alpha: 0.04),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
          child: Row(
            children: [
              Icon(Icons.folder_rounded, color: _cyan.withValues(alpha: 0.8), size: 18),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  project.name,
                  style: const TextStyle(color: Colors.white, fontWeight: FontWeight.w600, fontSize: 14),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 12),
              // Status chips — fixed position, right-aligned
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  if (project.scanComplete) _statusChip('SCANNED', const Color(0xFF00FF88)),
                  if (project.analysisComplete) _statusChip('ANALYZED', _cyan),
                  if (project.hasResults) _statusChip('RESULTS', const Color(0xFFFFAA00)),
                ],
              ),
              const SizedBox(width: 12),
              // Date + tokens — fixed width column
              SizedBox(
                width: 160,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.end,
                  children: [
                    Text(dateStr, style: const TextStyle(color: Colors.white38, fontSize: 11)),
                    if (tokens > 0)
                      Text('~${_fmtTokens(tokens)} tokens', style: const TextStyle(color: Colors.white24, fontSize: 10)),
                  ],
                ),
              ),
              const SizedBox(width: 4),
              IconButton(
                icon: const Icon(Icons.download, color: Colors.white38, size: 16),
                onPressed: () => ProjectPorter.exportProject(project, context),
                tooltip: 'Export project',
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
              ),
              IconButton(
                icon: const Icon(Icons.delete_outline, color: Colors.white24, size: 16),
                onPressed: () => _deleteProject(project),
                tooltip: 'Delete project',
                visualDensity: VisualDensity.compact,
                padding: EdgeInsets.zero,
                constraints: const BoxConstraints(minWidth: 32, minHeight: 32),
              ),
            ],
          ),
        ),
      ),
    );
  }

  String _fmtTokens(int n) {
    if (n >= 1000000) return '${(n / 1000000).toStringAsFixed(1)}M';
    if (n >= 1000) return '${(n / 1000).toStringAsFixed(0)}K';
    return n.toString();
  }

  Widget _statusChip(String label, Color color) {
    return Container(
      margin: const EdgeInsets.only(right: 6),
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.15),
        borderRadius: BorderRadius.circular(4),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Text(label, style: TextStyle(color: color, fontSize: 9, fontWeight: FontWeight.bold)),
    );
  }
}
