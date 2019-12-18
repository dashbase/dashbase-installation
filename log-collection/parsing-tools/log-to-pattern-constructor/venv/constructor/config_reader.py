import re
import os
import logging

class ConfigReader:

    def __init__(self):
        self.xLogs = []
        self.logSample =''
        package_dir = os.path.dirname(os.path.abspath(__file__))
        self.logSampleFileName = os.path.join(package_dir, 'log')
        self.kamailioConfig = os.path.join(package_dir, 'kamailio.cfg')
        self.readLogSample()
        self.readXlogFromKamailioConfig()

    def readLogSample(self):
        with open(self.logSampleFileName) as fp:
            try:
                line = fp.readline()
                cnt = 1
                while line:
                    logging.info("Reading Line {}: {}".format(cnt, line.strip()))

                    #Store last line in sample log
                    if len(line) > 0:
                        self.logSample = line.strip()
                    line = fp.readline()
                    cnt += 1
            except:
                logging.error("Failed to read sample log file.")
            finally:
                fp.close()
        return self

    def readXlogFromKamailioConfig(self):
        with open(self.kamailioConfig) as fp:
            try:
                line = fp.readline()
                cnt = 1
                while line:
                    #Store all of them
                    regex = r"xlog(.*);"
                    matches = re.finditer(regex, line, re.MULTILINE)
                    for matchNum, match in enumerate(matches, start=1):
                        logging.debug("Match {matchNum} was found at {start}-{end}: {match}".format(matchNum=matchNum,
                                                                                             start=match.start(),
                                                                                             end=match.end(),
                                                                                             match=match.group()))
                        self.xLogs.append(match.group())
                    line = fp.readline()
                    cnt += 1
            except:
                logging.error("Failed to read xlog config file.")
            finally:
                fp.close()
        return self




#configReader = ConfigReader()
#print(configReader.xLogs)
