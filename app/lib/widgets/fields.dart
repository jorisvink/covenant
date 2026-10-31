// Text inputs and choices, drawn like the Pre blocks and panels.

import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import '../theme.dart';
import 'buttons.dart';
import 'ui.dart';

TextInputType get addressKeyboard => defaultTargetPlatform == TargetPlatform.iOS
    ? const TextInputType.numberWithOptions(signed: true, decimal: true)
    : TextInputType.text;

class Field extends StatelessWidget {
  const Field({
    super.key,
    required this.controller,
    this.hint,
    this.allow,
    this.maxLength,
    this.lines = 1,
    this.keyboard,
    this.onChanged,
  });

  final TextEditingController controller;
  final String? hint;
  final RegExp? allow;
  final int? maxLength;
  final int lines;
  final TextInputType? keyboard;
  final ValueChanged<String>? onChanged;

  @override
  Widget build(BuildContext context) {
    return Pre(
      child: TextField(
        controller: controller,
        maxLength: maxLength,
        minLines: lines,
        maxLines: lines == 1 ? 1 : lines + 6,
        autocorrect: false,
        enableSuggestions: false,
        enableIMEPersonalizedLearning: false,
        keyboardType: lines > 1 ? TextInputType.multiline : keyboard,
        textInputAction: lines > 1
            ? TextInputAction.newline
            : TextInputAction.done,
        inputFormatters: [
          if (allow != null) FilteringTextInputFormatter.allow(allow!),
        ],
        onChanged: onChanged,
        style: Styles.pre,
        cursorColor: Palette.amber,
        decoration: InputDecoration.collapsed(
          hintText: hint,
          hintStyle: Styles.pre.copyWith(color: Palette.dim),
        ).copyWith(counterText: ''),
      ),
    );
  }
}

/// A row of options of which one is picked, like a segmented control.
class Choice<T> extends StatelessWidget {
  const Choice({
    super.key,
    required this.options,
    required this.value,
    required this.onChanged,
  });

  final List<(T, String)> options;
  final T value;
  final ValueChanged<T> onChanged;

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        for (var i = 0; i < options.length; i++) ...[
          if (i > 0) const SizedBox(width: 6),
          Expanded(
            child: Pressable(
              onTap: () => onChanged(options[i].$1),
              label: options[i].$2,
              builder: (context, pressed) {
                final on = options[i].$1 == value;

                return Container(
                  height: 40,
                  alignment: Alignment.center,
                  decoration: BoxDecoration(
                    color: on
                        ? Palette.amberWash
                        : pressed
                        ? Palette.bg3
                        : Palette.bg2,
                    border: Border.all(
                      color: on ? Palette.amber : Palette.line2,
                    ),
                  ),
                  child: Text(
                    options[i].$2.toUpperCase(),
                    style: Styles.tab.copyWith(
                      fontSize: 10.5,
                      color: on ? Palette.amber : Palette.fg2,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                );
              },
            ),
          ),
        ],
      ],
    );
  }
}

/// A panel with an explanation and a toggle.
class SwitchRow extends StatelessWidget {
  const SwitchRow({
    super.key,
    required this.text,
    required this.on,
    required this.onChanged,
    this.label,
  });

  final String text;
  final bool on;
  final ValueChanged<bool> onChanged;
  final String? label;

  @override
  Widget build(BuildContext context) {
    return Panel(
      padding: const EdgeInsets.fromLTRB(16, 14, 6, 14),
      child: Row(
        children: [
          Expanded(child: Text(text, style: Styles.body)),
          Toggle(on: on, label: label ?? text, onTap: () => onChanged(!on)),
        ],
      ),
    );
  }
}
