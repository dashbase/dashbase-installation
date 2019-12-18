import re
import logging

class XlogFormatDecoder:

    def __init__(self, log):
        self.logConfig = log
        try:
            x = re.findall("xlog(.*);", self.logConfig)
            self.logConfig = "".join(x).split(',')[1][1:-4].strip()
            self.get_pattern()
            logging.debug("XLog: " + log)
            logging.debug("XLog Pattern: " + self.logConfig)
        except:
            logging.error("Error Parsing xlog facility and level")
            self.logConfig = ''

    def get_pattern(self):
        regex = r"[$][a-zA-Z1-9]{1,256}([(][a-z]{1,256}[)])?"

        matches = re.finditer(regex, self.logConfig, re.MULTILINE)

        for matchNum, match in enumerate(matches, start=1):
            logging.debug ("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum=matchNum, start=match.start(),
                                                                                 end=match.end(), match=match.group()))
            self.logConfig = self.logConfig.replace(match.group(), "%{{DATA:{var}}}".format(
                var=match.group().replace('$', '').replace("(", "-").replace(")", '')))

        logging.info(self.logConfig)
        temp = self.logConfig
        logging.info(re.escape(temp))
        return self

'''
print("TestCase1")
log = "xlog(\"L_INFO\",\"[$cfg(route)] *New request $rm* rU=$rU/tU=$tU/fU=$fU/rd=$rd/si=$si/sp=$sp \\n\");"
decoder = XlogFormatDecoder(log)

print("\nTestCase2")

log = "xlog(\"L_ALERT\",\"ALERT: pike blocking $rm from $fu (IP:$si:$sp)\\n\");"
decoder = XlogFormatDecoder(log)

'''
