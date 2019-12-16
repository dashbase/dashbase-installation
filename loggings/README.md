### Asterisk Logging Script

#### Limitations
Asterisk used strftime specifiers in `dateformat` field to format the time(https://wiki.asterisk.org/wiki/display/AST/Logging+Configuration).
This script will handle the `dateformat` field. But it
1. Doesn't handle Modifier(`%O` and `%E`) in strftime
2. Doesn't support the glibc extensions for conversion specifications. All the additional specifications will be regarded as literal values.
   (e.g. an optional flag and field width may be specified.)

Ref: http://man7.org/linux/man-pages/man3/strftime.3.html