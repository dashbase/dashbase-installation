# -*- coding: utf-8 -*-
import os
import sys
import locale

if sys.version > '3':
    import configparser
else:
    import ConfigParser as configparser

########################################################################################################################
# See source code in https://github.com/apache/tomcat/blob/master/java/org/apache/catalina/util/Strftime.java#L52-L105

PATTERNS = {
    "%a": "EEE",
    "%A": "EEEE",
    "%b": "MMM",
    "%B": "MMMM",
    "%c": "EEE MMM d HH:mm:ss yyyy",
    "%d": "dd",
    "%D": "MM/dd/yy",
    "%e": "dd",
    "%F": "yyyy-MM-dd",
    "%g": "yy",
    "%G": "yyyy",
    "%h": "MMM",
    "%H": "HH",
    "%I": "hh",
    "%j": "DDD",
    "%k": "HH",
    "%l": "hh",
    "%m": "MM",
    "%M": "mm",
    "%n": "\n",
    "%p": "a",
    "%P": "a",
    "%r": "hh:mm:ss a",
    "%R": "HH:mm",
    "%S": "ss",
    "%t": "\t",
    "%T": "HH:mm:ss",
    "%V": "ww",
    "%x": "MM/dd/yy",
    "%X": "HH:mm:ss",
    "%y": "yy",
    "%Y": "yyyy",
    "%z": "Z",
    "%Z": "z",
    "%%": "%"
}


def quote(str, inside_quotes):
    return "'" + str + "'" if inside_quotes else str


def translate_command(buffer, pattern, index, old_inside):
    first_char = pattern[index]
    new_inside = old_inside

    if first_char == 'O' or first_char == 'E':
        if index + 1 < len(pattern):
            new_inside, buffer = translate_command(buffer, pattern, index + 1, old_inside)
        else:
            buffer += quote("%" + first_char, old_inside)
    else:
        command = PATTERNS.get("%" + first_char, None)
        if not command:
            print("Found unsupported specifications: %{}".format(first_char))
            exit(1)
        else:
            if old_inside:
                buffer += "'"
            buffer += command
            new_inside = False
    return new_inside, buffer


# TODO:
#   1. Fix pattern like "%.3q"
#   2. Fix ', ",( ,), [, ] in pattern
def convert_dateformat(pattern):
    inside = False
    mark = False
    modified_command = False
    buffer = ""

    for index, char in enumerate(pattern):
        if char == '%' and not mark:
            mark = True
        else:
            if mark:
                if modified_command:
                    # don't do anything--we just wanted to skip a char
                    modified_command = False
                    mark = False
                else:
                    inside, buffer = translate_command(buffer, pattern, index, inside)
                    if char == 'O' or char == 'E':
                        modified_command = True
                    else:
                        mark = False
            else:
                if not inside and char != ' ':
                    buffer += "'"
                    inside = True

                buffer += char if char != "'" else "''"

    if len(buffer) > 0:
        if inside:
            buffer += "'"
    return buffer


########################################################################################################################

class AsteriskGeneral():
    use_callids = True
    dateformat = ''
    appendhostname = True
    queue_log = True

    def get_pattern(self):
        if self.dateformat:
            pattern = '\[%{GREEDYDATA:timestamp:datetime:' + convert_dateformat(self.dateformat) + '}\] '
        else:
            pattern = '\[%{SYSLOGTIMESTAMP:timestamp:datetime:MMM ppd HH:mm:ss}\\] '

        pattern += '%{WORD:level:meta}\[%{INT:lwp:int}\]'
        if self.use_callids:
            pattern += '(\[%{DATA:callid:text}\])?'
        pattern += ' '

        pattern += '%{JAVAFILE:source:meta}: %{GREEDYDATA:message}'

        return pattern


def get_pattern(section):
    general = AsteriskGeneral()

    general.use_callids = section.get('use_callids', 'yes') == 'yes'

    general.appendhostname = section.get('appendhostname', 'no') == 'yes'

    general.dateformat = section.get('dateformat', '')

    general.queue_log = section.get('queue_log', 'yes') == 'yes'

    return general.get_pattern()


def read_config_file(filename):
    print("Reading file: {}".format(filename))

    buffer = ''

    if not os.path.isfile(filename):
        print("File {} is not found".format(filename, flush=True))
        return buffer

    with open(filename, 'r') as f:
        while True:
            line = f.readline()
            if not line:
                return buffer
            if not line.startswith("#include"):
                buffer += line
            else:
                _, file = line.rsplit(maxsplit=2)
                include_filename = os.path.join(os.path.dirname(filename), file)
                buffer += read_config_file(include_filename)


if __name__ == '__main__':
    if locale.getdefaultlocale()[0] != 'en_US':
        print("This machine is not in the locale of 'en_US'. This may break the dashbase parsing because Asterisk "
              "will output log according to the current locale")

    # TODO input config file path
    buffer = read_config_file('../logger.conf')

    try:
        config = configparser.ConfigParser(interpolation=configparser.Interpolation())

        config.read_string(buffer)

        if 'general' not in config:
            print("Section 'general' is not found in the config files. "
                  "These config files are considered as broken ones.")
            exit(1)

        pattern = config['general'].get('dateformat')

        print("Your pattern is: '{}'".format(get_pattern(config['general'])))
    except configparser.ParsingError as e:
        print(e)