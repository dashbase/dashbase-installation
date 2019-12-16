### Asterisk Logging Script

Limitations:
1. This script doesn't handle Modifier(`%O` and `%E`) in strftime
2. This script doesn't support the glibc extensions for conversion specifications. All the additional specifications will be regarded as literal values.
   (e.g. an optional flag and field width may be specified.)

Ref: http://man7.org/linux/man-pages/man3/strftime.3.html