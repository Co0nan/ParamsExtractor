from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
import sys
from javax import swing
from java.awt import Font, Color
from javax.swing import JFileChooser
from burp import ITab


class BurpExtender(IBurpExtender, IScannerCheck, ITab):

	def registerExtenderCallbacks(self, callbacks):
		self._callbacks = callbacks
		self._helpers = callbacks.getHelpers()

		callbacks.setExtensionName("ParamsExtractor")

		sys.stdout = callbacks.getStdout()
		sys.stderr = callbacks.getStderr()

		callbacks.registerScannerCheck(self)
		self.initUI()
		callbacks.addSuiteTab(self)

	def initUI(self):
		self.tab = swing.JPanel()

		self.outputLabel = swing.JLabel("ParamsExtractor log : ")
		self.outputLabel.setFont(Font("Tahoma", Font.BOLD,14))
		self.outputLabel.setForeground(Color(255,102,52))
		self.logPane = swing.JScrollPane()
		self.outputTxtArea = swing.JTextArea()
		self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
		self.outputTxtArea.setLineWrap(True)
		self.logPane.setViewportView(self.outputTxtArea)
		self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
		self.exportBtn = swing.JButton("Export Log", actionPerformed=self.exportLog)
		self.parentFrm = swing.JFileChooser()

		layout = swing.GroupLayout(self.tab)
		layout.setAutoCreateGaps(True)
		layout.setAutoCreateContainerGaps(True)
		self.tab.setLayout(layout)
			
		layout.setHorizontalGroup(
			layout.createParallelGroup()
			.addGroup(layout.createSequentialGroup()
				.addGroup(layout.createParallelGroup()
					.addComponent(self.outputLabel)
					.addComponent(self.logPane)
					.addComponent(self.clearBtn)
					.addComponent(self.exportBtn)
				)
			)
		)
				
		layout.setVerticalGroup(
			layout.createParallelGroup()
			.addGroup(layout.createParallelGroup()
				.addGroup(layout.createSequentialGroup()
					.addComponent(self.outputLabel)
					.addComponent(self.logPane)
					.addComponent(self.clearBtn)
					.addComponent(self.exportBtn)
				)
			)
		)

	
	def getTabCaption(self):
		return "ParamsExtractor"
    
	def getUiComponent(self):
		return self.tab


	def _check_params(self, reqInfo):
		findings = []
		params = reqInfo.getParameters()
		url = reqInfo.getUrl()
		for param in params:
			name = param.getName()
			value = param.getValue()
			if name not in findings:
				findings.append(name)

		return findings

	def clearLog(self, event):
		self.outputTxtArea.setText("")

	def exportLog(self, event):
		chooseFile = JFileChooser()
		ret = chooseFile.showDialog(self.logPane, "Choose file")
		filename = chooseFile.getSelectedFile().getCanonicalPath()
		print("\n" + "Export to : " + filename)
		open(filename, 'w', 0).write(self.outputTxtArea.text)

	def doPassiveScan(self, baseRequestResponse):
		if self._callbacks.isInScope(self._helpers.analyzeRequest(baseRequestResponse).getUrl()):

			analyzed = self._helpers.analyzeRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest())
			matchesArray = self._check_params(analyzed)
			matches = list(dict.fromkeys(matchesArray))
			if len(matches) == 0:
				return None

			#print(matches)
			#print(type(matches))
			for param in matches:
				if param not in self.outputTxtArea.text:
					self.outputTxtArea.append(str(param)+"\n")
		else:
			print("Out of Scope")
			print(self._helpers.analyzeRequest(baseRequestResponse).getUrl())


	def consolidateDuplicateIssues(self, existingIssue, newIssue):
		return -1
