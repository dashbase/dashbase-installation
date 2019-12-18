import sys
import os
from config_reader import ConfigReader
from log_pattern_builder import LogToPatternBuilder
from xlog_format_decoder import XlogFormatDecoder
import os
import yaml
import logging

dict_list = []


def writeConfig():
    package_dir = os.path.dirname(os.path.abspath(__file__))
    patternConfig = os.path.join(package_dir, 'kamailio.yaml')

    with open(patternConfig, "a+") as fp:
        try:
            fp.truncate(0)
            fp.write("\n")
            yaml.dump(dict_list, fp)
        except:
            logging.error("Failed to dump YAML config.")
        finally:
            fp.close()


def buildConfig(pattern, patternType):
    dict_file = {"pattern": pattern, "type": 'grok', "multiline.pattern": '^.', "multiline.negate": True,
                 "multiline.match": 'after'}
    dict_list.append({patternType: dict_file});


def main():
    logging.basicConfig(level=logging.DEBUG)
    configReader = ConfigReader()
    builder = LogToPatternBuilder(configReader.logSample)
    count = 0
    for xLog in configReader.xLogs:
        decoder = XlogFormatDecoder(xLog)
        pattern = builder.pattern
        if len(decoder.logConfig) > 0:
            pattern += decoder.logConfig
            logging.debug(pattern)
            count = count + 1
            buildConfig(pattern, "patternType" + str(count))
    writeConfig()
    logging.debug('Done! I am going home. (Good)Bye!')


if __name__ == '__main__':
    main()
