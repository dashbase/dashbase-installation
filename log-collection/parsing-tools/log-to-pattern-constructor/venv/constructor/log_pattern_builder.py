import re

class LogToPatternBuilder:

    DATE_PATTERNS_FORMAT_DICT = {}

    def __init__(self, logSample):
        self.logSample = logSample
        self.pattern = self.find_pattern_from_log()


    def find_pattern_from_log(self):
        self.pattern = ''
        matches = re.findall("[a-zA-Z]{3} \d{2} \d{2}:\d{2}:\d{2}", self.logSample)
        date = "".join(matches)
        if len(date) > 0:
            self.pattern += "%{DATA:timestamp:datetime:MMM ppd HH:mm:ss} "

        #TODO: test and chnage it to \b(?:[0-9A-Za-z][0-9A-Za-z-]{0,62})(?:\.(?:[0-9A-Za-z][0-9A-Za-z-]{0,62}))*(\.?|\b)
        matches = re.findall("[a-zA-Z1-9]{1,3}-[a-zA-Z1-9]{1,3}-[a-zA-Z1-9]{1,3}-[a-zA-Z1-9]{1,3}-[a-zA-Z1-9]{1,3}", self.logSample)
        ip = "".join(matches)
        if len(ip) > 0:
            self.pattern += "(?:%{SYSLOGFACILITY} )?%{SYSLOGHOST:logsource:meta} %{SYSLOGPROG}: (%{DATA:pid})? "

        # level - The level that will be used in LOG function. It can be:
        # L_ALERT - log level -5
        # L_BUG - log level -4
        # L_CRIT - log level -3
        # L_ERR - log level -1
        # L_WARN - log level 0
        # L_NOTICE - log level 1
        # L_INFO - log level 2
        # L_DBG - log level 3
        log_level_list = {"ALERT","BUG","CRIT","ERR","WARN","NOTICE","INFO","DBG"}

        for log_level in log_level_list:
            matches = re.findall(log_level,
                           self.logSample)
            if len(matches) > 0:
                self.pattern += "%{LOGLEVEL:level:meta}: "
                break

        matches = re.findall("[<][a-zA-Z]{1,10}[>]:", self.logSample)
        script = "".join(matches)
        if len(script) > 0:
            self.pattern += "%{DATA:script}:? "

        return self.pattern


#builder = LogToPatternBuilder("Nov 20 11:45:07 ip-192-168-12-214 kamailio: 4(27089) INFO: <script>: [DEFAULT_ROUTE] *New request INVITE* rU=1008/tU=1008/fU=1007/rd=192.168.12.214/si=172.17.0.10/sp=39531")
#print(builder.pattern)
