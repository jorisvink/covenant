import 'dart:async';

import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';

import 'core.dart';
import 'pages/about.dart';
import 'pages/account.dart';
import 'pages/flock.dart';
import 'pages/flocks.dart';
import 'pages/keys.dart';
import 'reliquary.dart';
import 'theme.dart';
import 'widgets/buttons.dart';
import 'widgets/fields.dart';
import 'widgets/marks.dart';
import 'widgets/ui.dart';

enum NavTab { flocks, keys, account, about }

const _tabs = [
  ('Flocks', GlyphKind.flocks),
  ('Keys', GlyphKind.keys),
  ('Account', GlyphKind.account),
  ('About', GlyphKind.about),
];

final GlobalKey<NavigatorState> navigatorKey = GlobalKey<NavigatorState>();
final ValueNotifier<NavTab> currentTab = ValueNotifier(NavTab.flocks);

class ReliquaryApp extends StatelessWidget {
  const ReliquaryApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Covenant',
      navigatorKey: navigatorKey,
      debugShowCheckedModeBanner: false,
      theme: _theme(),
      builder: (context, child) => Material(
        type: MaterialType.transparency,
        child: DefaultTextStyle(
          style: Styles.body,
          child: _Veil(child: child!),
        ),
      ),
      home: const Shell(),
    );
  }

  ThemeData _theme() {
    return ThemeData(
      brightness: Brightness.dark,
      useMaterial3: true,
      splashFactory: NoSplash.splashFactory,
      highlightColor: const Color(0x00000000),
      scaffoldBackgroundColor: Palette.bg,
      canvasColor: Palette.bg,
      colorScheme: const ColorScheme.dark(
        primary: Palette.amber,
        onPrimary: Palette.bg,
        secondary: Palette.amber2,
        surface: Palette.bg,
        onSurface: Palette.fg2,
        error: Palette.amber,
      ),
      textSelectionTheme: const TextSelectionThemeData(
        cursorColor: Palette.amber,
        selectionColor: Color(0x99ffb000),
        selectionHandleColor: Palette.amber,
      ),
      textTheme: const TextTheme(bodyMedium: Styles.body),
    );
  }
}

/// Covers the app while it is not in front so the app switcher never
/// shows a QR code or an account key.
class _Veil extends StatefulWidget {
  const _Veil({required this.child});

  final Widget child;

  @override
  State<_Veil> createState() => _VeilState();
}

class _VeilState extends State<_Veil> with WidgetsBindingObserver {
  bool _hidden = false;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    final hidden = state != AppLifecycleState.resumed;

    if (hidden != _hidden) {
      setState(() => _hidden = hidden);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        widget.child,
        if (_hidden)
          const Positioned.fill(
            child: ColoredBox(
              color: Palette.bg,
              child: Center(child: WordmarkSquare(size: 44)),
            ),
          ),
      ],
    );
  }
}

class Shell extends StatefulWidget {
  const Shell({super.key});

  @override
  State<Shell> createState() => _ShellState();
}

class _ShellState extends State<Shell> with WidgetsBindingObserver {
  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    unawaited(Reliquary.instance.start());
    _reminded();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed) {
      _reminded();
    }
  }

  Future<void> _reminded() async {
    final String? flock;

    try {
      flock = await Reliquary.instance.core.remindedFlock();
    } on CoreError {
      return;
    }

    if (flock == null || !mounted) {
      return;
    }

    goTab(NavTab.flocks);

    if (Reliquary.instance.session != null) {
      push(FlockPage(id: flock)).ignore();
    }
  }

  @override
  Widget build(BuildContext context) {
    return DotGrid(
      child: ValueListenableBuilder<NavTab>(
        valueListenable: currentTab,
        builder: (context, tab, _) => Stack(
          children: [
            Positioned.fill(
              child: IndexedStack(
                index: tab.index,
                children: [
                  for (final t in NavTab.values)
                    TickerMode(
                      enabled: t == tab,
                      child: switch (t) {
                        NavTab.flocks => const FlocksPage(),
                        NavTab.keys => const KeysPage(),
                        NavTab.account => const AccountPage(),
                        NavTab.about => const AboutPage(),
                      },
                    ),
                ],
              ),
            ),
            Positioned(
              left: 0,
              right: 0,
              bottom: 0,
              height: tabBarSpace(context),
              child: const IgnorePointer(
                child: DecoratedBox(
                  decoration: BoxDecoration(
                    gradient: LinearGradient(
                      begin: Alignment.topCenter,
                      end: Alignment.bottomCenter,
                      colors: [Color(0x000b0c0e), Palette.bg],
                      stops: [0, 0.45],
                    ),
                  ),
                ),
              ),
            ),
            Positioned(
              left: 12,
              right: 12,
              bottom: MediaQuery.paddingOf(context).bottom + 12,
              child: _TabBar(current: tab),
            ),
          ],
        ),
      ),
    );
  }
}

class _TabBar extends StatelessWidget {
  const _TabBar({required this.current});

  final NavTab current;

  @override
  Widget build(BuildContext context) {
    return Container(
      decoration: const BoxDecoration(
        boxShadow: [
          BoxShadow(color: Color(0xcc000000), blurRadius: 24, spreadRadius: 4),
        ],
      ),
      child: CustomPaint(
        painter: const CutPainter(fill: Palette.bg2, stroke: Palette.line2),
        child: SizedBox(
          height: Metrics.tabBar,
          child: Row(
            children: [
              for (final tab in NavTab.values)
                Expanded(
                  child: _TabItem(
                    label: _tabs[tab.index].$1,
                    glyph: _tabs[tab.index].$2,
                    active: tab == current,
                    onTap: () => goTab(tab),
                  ),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

class _TabItem extends StatelessWidget {
  const _TabItem({
    required this.label,
    required this.glyph,
    required this.active,
    required this.onTap,
  });

  final String label;
  final GlyphKind glyph;
  final bool active;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Pressable(
      onTap: onTap,
      label: label,
      builder: (context, pressed) {
        final color = active || pressed ? Palette.amber : Palette.dim;

        return Stack(
          children: [
            Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Glyph(glyph, size: 22, color: color),
                  const SizedBox(height: 7),
                  Text(
                    label.toUpperCase(),
                    style: Styles.tab.copyWith(
                      color: active ? Palette.fg : color,
                    ),
                  ),
                ],
              ),
            ),
            if (active)
              Positioned(
                top: 0,
                left: 0,
                right: 0,
                child: Center(
                  child: Container(width: 26, height: 2, color: Palette.amber),
                ),
              ),
          ],
        );
      },
    );
  }
}

void goTab(NavTab tab) {
  navigatorKey.currentState?.popUntil((route) => route.isFirst);
  currentTab.value = tab;
}

Route<T> route<T>(Widget page) {
  return PageRouteBuilder<T>(
    pageBuilder: (context, _, _) => page,
    transitionDuration: const Duration(milliseconds: 220),
    reverseTransitionDuration: const Duration(milliseconds: 160),
    transitionsBuilder: (context, animation, _, child) {
      final curved = CurvedAnimation(
        parent: animation,
        curve: Curves.easeOutCubic,
        reverseCurve: Curves.easeInCubic,
      );

      return FadeTransition(
        opacity: curved,
        child: SlideTransition(
          position: Tween(
            begin: const Offset(0.06, 0),
            end: Offset.zero,
          ).animate(curved),
          child: child,
        ),
      );
    },
  );
}

Future<T?> push<T>(Widget page) {
  return navigatorKey.currentState!.push<T>(route<T>(page));
}

Future<T?> replace<T>(Widget page) {
  return navigatorKey.currentState!.pushReplacement<T, Object?>(route<T>(page));
}

void open(String url) {
  unawaited(launchUrl(Uri.parse(url), mode: LaunchMode.externalApplication));
}

OverlayEntry? _toast;

void notify(String message, {bool warn = true}) {
  final overlay = navigatorKey.currentState?.overlay;
  if (overlay == null) {
    return;
  }

  _toast?.remove();

  late final OverlayEntry entry;

  entry = OverlayEntry(
    builder: (context) => Positioned(
      left: Metrics.edge,
      right: Metrics.edge,
      bottom: tabBarSpace(context),
      child: IgnorePointer(
        child: TweenAnimationBuilder<double>(
          tween: Tween(begin: 0, end: 1),
          duration: const Duration(milliseconds: 180),
          builder: (context, t, child) => Opacity(
            opacity: t,
            child: Transform.translate(
              offset: Offset(0, (1 - t) * 12),
              child: child,
            ),
          ),
          child: Material(
            type: MaterialType.transparency,
            child: Container(
              decoration: const BoxDecoration(
                boxShadow: [
                  BoxShadow(color: Color(0xcc000000), blurRadius: 20),
                ],
              ),
              child: Notice(
                text: message,
                kind: warn ? NoticeKind.warn : NoticeKind.good,
              ),
            ),
          ),
        ),
      ),
    ),
  );

  _toast = entry;
  overlay.insert(entry);

  Timer(const Duration(seconds: 4), () {
    if (_toast == entry) {
      _toast = null;
    }

    if (entry.mounted) {
      entry.remove();
    }
  });
}

/// Run an operation the user has to wait for. The app is covered with a
/// work panel until it is done so nothing else can be started meanwhile.
Future<T> wait<T>(String text, Future<T> Function() work) async {
  final navigator = navigatorKey.currentState!;

  FocusManager.instance.primaryFocus?.unfocus();
  _toast?.remove();
  _toast = null;

  final route = RawDialogRoute<void>(
    barrierDismissible: false,
    barrierColor: const Color(0xcc0b0c0e),
    transitionDuration: const Duration(milliseconds: 160),
    pageBuilder: (context, _, _) =>
        PopScope(canPop: false, child: _Waiting(text: text)),
  );

  navigator.push(route).ignore();

  try {
    return await work();
  } finally {
    if (route.isActive) {
      navigator.removeRoute(route);
    }
  }
}

class _Waiting extends StatelessWidget {
  const _Waiting({required this.text});

  final String text;

  @override
  Widget build(BuildContext context) {
    final r = Reliquary.instance;

    return ListenableBuilder(
      listenable: r,
      builder: (context, _) {
        final work = r.work;

        return SafeArea(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: Metrics.edge),
            child: Center(
              child: WorkPanel(
                text: work?.step ?? (r.loading ? 'Loading your flocks' : text),
                progress: work != null ? work.progress : r.loaded,
              ),
            ),
          ),
        );
      },
    );
  }
}

Future<bool> confirm({
  required String title,
  required String text,
  required String action,
}) async {
  final context = navigatorKey.currentContext;
  if (context == null) {
    return false;
  }

  FocusManager.instance.primaryFocus?.unfocus();

  final result = await showModalBottomSheet<bool>(
    context: context,
    backgroundColor: const Color(0x00000000),
    barrierColor: const Color(0xcc0b0c0e),
    elevation: 0,
    isScrollControlled: true,
    builder: (context) => CustomPaint(
      painter: const CutPainter(fill: Palette.bg2, stroke: Palette.line2),
      child: Padding(
        padding: EdgeInsets.fromLTRB(
          Metrics.edge,
          14,
          Metrics.edge,
          MediaQuery.paddingOf(context).bottom + 18,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(width: 32, height: 3, color: Palette.amber),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                const RubricCross(fill: Palette.bg2),
                const SizedBox(width: 12),
                Expanded(child: Text(title, style: Styles.cardTitle)),
              ],
            ),
            const SizedBox(height: 12),
            Text(text, style: Styles.body),
            const SizedBox(height: 24),
            BtnPair(
              first: Btn(
                label: 'Cancel',
                kind: BtnKind.secondary,
                expand: true,
                onTap: () => Navigator.of(context).pop(false),
              ),
              second: Btn(
                label: action,
                expand: true,
                onTap: () => Navigator.of(context).pop(true),
              ),
            ),
          ],
        ),
      ),
    ),
  );

  return result ?? false;
}

Future<String?> ask({
  required String title,
  required String text,
  required String action,
  String initial = '',
  String? hint,
  int? maxLength,
}) async {
  final context = navigatorKey.currentContext;
  if (context == null) {
    return null;
  }

  FocusManager.instance.primaryFocus?.unfocus();

  final controller = TextEditingController(text: initial);

  final result = await showModalBottomSheet<String>(
    context: context,
    backgroundColor: const Color(0x00000000),
    barrierColor: const Color(0xcc0b0c0e),
    elevation: 0,
    isScrollControlled: true,
    builder: (context) => Padding(
      padding: EdgeInsets.only(bottom: MediaQuery.viewInsetsOf(context).bottom),
      child: CustomPaint(
        painter: const CutPainter(fill: Palette.bg2, stroke: Palette.line2),
        child: Padding(
          padding: EdgeInsets.fromLTRB(
            Metrics.edge,
            14,
            Metrics.edge,
            MediaQuery.paddingOf(context).bottom + 18,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Center(
                child: Container(width: 32, height: 3, color: Palette.amber),
              ),
              const SizedBox(height: 20),
              Row(
                children: [
                  const RubricCross(fill: Palette.bg2),
                  const SizedBox(width: 12),
                  Expanded(child: Text(title, style: Styles.cardTitle)),
                ],
              ),
              const SizedBox(height: 12),
              Text(text, style: Styles.body),
              const SizedBox(height: 16),
              Field(
                controller: controller,
                hint: hint,
                maxLength: maxLength,
                autofocus: true,
                onSubmitted: (v) => Navigator.of(context).pop(v.trim()),
              ),
              const SizedBox(height: 24),
              BtnPair(
                first: Btn(
                  label: 'Cancel',
                  kind: BtnKind.secondary,
                  expand: true,
                  onTap: () => Navigator.of(context).pop(),
                ),
                second: Btn(
                  label: action,
                  expand: true,
                  onTap: () =>
                      Navigator.of(context).pop(controller.text.trim()),
                ),
              ),
            ],
          ),
        ),
      ),
    ),
  );

  controller.dispose();
  return result;
}

Future<T?> choose<T>({
  required String title,
  required List<(T, String, String?)> options,
}) {
  final context = navigatorKey.currentContext;
  if (context == null) {
    return Future.value(null);
  }

  FocusManager.instance.primaryFocus?.unfocus();

  return showModalBottomSheet<T>(
    context: context,
    backgroundColor: const Color(0x00000000),
    barrierColor: const Color(0xcc0b0c0e),
    elevation: 0,
    isScrollControlled: true,
    builder: (context) => CustomPaint(
      painter: const CutPainter(fill: Palette.bg2, stroke: Palette.line2),
      child: Padding(
        padding: EdgeInsets.fromLTRB(
          Metrics.edge,
          14,
          Metrics.edge,
          MediaQuery.paddingOf(context).bottom + 18,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Center(
              child: Container(width: 32, height: 3, color: Palette.amber),
            ),
            const SizedBox(height: 20),
            Row(
              children: [
                const RubricCross(fill: Palette.bg2),
                const SizedBox(width: 12),
                Expanded(child: Text(title, style: Styles.cardTitle)),
              ],
            ),
            const SizedBox(height: 16),
            ConstrainedBox(
              constraints: BoxConstraints(
                maxHeight: MediaQuery.sizeOf(context).height * 0.6,
              ),
              child: SingleChildScrollView(
                child: LinkList(
                  rows: [
                    for (final o in options)
                      LinkRow(
                        o.$2,
                        () => Navigator.of(context).pop(o.$1),
                        detail: o.$3,
                      ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    ),
  );
}

Future<int?> chooseDays() => choose<int>(
  title: 'How long should the encrypted secrets stay valid?',
  options: const [
    (7, '7 days', null),
    (30, '30 days', null),
    (90, '90 days', null),
    (365, '1 year', null),
  ],
);

String date(DateTime when) {
  String two(int v) => v.toString().padLeft(2, '0');
  return '${when.year}-${two(when.month)}-${two(when.day)}';
}

String dateTime(DateTime when) {
  String two(int v) => v.toString().padLeft(2, '0');
  return '${date(when)} ${two(when.hour)}:${two(when.minute)}';
}
