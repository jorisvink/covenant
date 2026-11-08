import 'dart:io';

final bool desktop = Platform.isLinux;

final String here = desktop ? 'computer' : 'phone';
