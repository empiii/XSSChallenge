## XSS Challenge - regEx apenas para tags h1 e script. inicio de lógica. 

from burp import IBurpExtender, IScannerCheck, IScanIssue
import re

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("XSS Detector")
        callbacks.registerScannerCheck(self)
        callbacks.issueAlert("XSS Detector extension loaded.")
        print("XSS Detector extension loaded.")
        return

    def getResponseHeadersAndBody(self, content):
        response = content.getResponse()
        response_data = self._helpers.analyzeResponse(response)
        headers = list(response_data.getHeaders())
        body = response[response_data.getBodyOffset():].tostring()
        return headers, body

    def detect_xss(self, parameter, body):
        if re.search(r"<{}>".format(re.escape(parameter)), body, re.IGNORECASE):
            return True
        return False

    def doPassiveScan(self, baseRequestResponse):
        issues = []
        headers, body = self.getResponseHeadersAndBody(baseRequestResponse)

        if self.detect_xss('script', body):
            self._callbacks.issueAlert("Potential XSS detected in response body.")
            issue = XSSScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                "Script tag reflection in response body",
                "High",
                self.getVulnerableLine('script', body)
            )
            issues.append(issue)

        if self.detect_xss('h1', body):
            self._callbacks.issueAlert("Potential XSS detected in response body.")
            issue = XSSScanIssue(
                baseRequestResponse.getHttpService(),
                self._helpers.analyzeRequest(baseRequestResponse).getUrl(),
                "unsanitized tag being reflected in response body, check information!",
                "High",
                self.getVulnerableLine('h1', body)
            )
            issues.append(issue)

        if not issues:
            issues = None

        return issues

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

    def getVulnerableLine(self, tag, body):
        lines = body.split('\n')
        for i, line in enumerate(lines, start=1):
            if re.search(r"<{}>".format(re.escape(tag)), line, re.IGNORECASE):
                return i
        return None

class XSSScanIssue(IScanIssue):
    def __init__(self, httpService, url, name, severity, vulnerableLine):
        self._httpService = httpService
        self._url = url
        self._name = name
        self._severity = severity
        self._vulnerableLine = vulnerableLine

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return "The parameter '{}' appears to be reflected in the response without proper sanitization, which could lead to a cross-site scripting (XSS) vulnerability. Vulnerable line: {}".format(self._name, self._vulnerableLine)

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
         return None

    def getHttpService(self):
        return self._httpService
