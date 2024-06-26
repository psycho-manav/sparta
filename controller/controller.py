#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool
(http://sparta.secforce.com)
Copyright (c) 2020 SECFORCE (Antonio Quina and Leonidas Stavliotis)

    This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys
import os
import ntpath
import signal
import re
import subprocess
import queue
from PyQt5.QtWidgets import QMenu, QApplication
from PyQt5.QtCore import QProcess, QTimer, QVariant, Qt
from app.logic import NmapImporter
from app.auxiliary import MyQProcess, Screenshooter, BrowserOpener, getTimestamp
from app.settings import Settings, AppSettings


class Controller():

    # initialisations that will happen once - when the program is launched
    def __init__(self, view, logic):
        self.version = 'SPARTA 2.0'
        self.logic = logic
        self.view = view
        self.view.setController(self)

        # creation of context menu actions from settings file and set up of various settings
        self.loadSettings()
        self.initNmapImporter()
        self.initScreenshooter()
        self.initBrowserOpener()
        # initialisations (globals, etc)
        self.start()
        self.initTimers()

    # initialisations that will happen everytime we create/open a project - can happen several times in the program's lifetime
    def start(self, title='*untitled'):
        # to store all the processes we run (nmaps, niktos, etc)
        self.processes = []
        # to manage fast processes (banner, snmpenum, etc)
        self.fastProcessQueue = queue.Queue()
        # counts the number of fast processes currently running
        self.fastProcessesRunning = 0
        # counts the number of slow processes currently running
        self.slowProcessesRunning = 0
        # tell nmap importer which db to use
        self.nmapImporter.setDB(self.logic.db)
        # tell screenshooter where the output folder is
        self.updateOutputFolder()
        self.view.start(title)

    def initNmapImporter(self):
        self.nmapImporter = NmapImporter()
        # update the progress bar
        self.nmapImporter.tick.connect(
            self.view.importProgressWidget.setProgress)
        self.nmapImporter.done.connect(self.nmapImportFinished)
        self.nmapImporter.schedule.connect(
            self.scheduler)              # run automated attacks

    def initScreenshooter(self):
        # screenshot taker object (different thread)
        self.screenshooter = Screenshooter(
            self.settings.general_screenshooter_timeout)
        self.screenshooter.done.connect(self.screenshotFinished)

    def initBrowserOpener(self):
        # browser opener object (different thread)
        self.browser = BrowserOpener()

    # these timers are used to prevent from updating the UI several times within a short time period - which freezes the UI
    def initTimers(self):
        self.updateUITimer = QTimer()
        self.updateUITimer.setSingleShot(True)
        self.updateUITimer.timeout.connect(self.view.updateProcessesTableView)
        self.updateUITimer.timeout.connect(self.view.updateToolsTableView)

        self.updateUI2Timer = QTimer()
        self.updateUI2Timer.setSingleShot(True)
        self.updateUI2Timer.timeout.connect(self.view.updateInterface)

    # this function fetches all the settings from the conf file. Among other things it populates the actions lists that will be used in the context menus.
    def loadSettings(self):
        self.settingsFile = AppSettings()
        # load settings from conf file (create conf file first if necessary)
        self.settings = Settings(self.settingsFile)
        # save the original state so that we can know if something has changed when we exit SPARTA
        self.originalSettings = Settings(self.settingsFile)
        self.logic.setStoreWordlistsOnExit(
            self.settings.brute_store_cleartext_passwords_on_exit == 'True')
#        self.view.settingsWidget.setSettings(Settings(self.settingsFile))

    # call this function when clicking 'apply' in the settings menu (after validation)
    def applySettings(self, newSettings):
        print('[+] Applying settings!')
        self.settings = newSettings

#    def cancelSettings(self):                                           # called when the user presses cancel in the Settings dialog
#        self.view.settingsWidget.setSettings(self.settings)             # resets the dialog's settings to the current application settings to forget any changes made by the user

    def saveSettings(self):
        if not self.settings == self.originalSettings:
            print('[+] Settings have been changed.')
            self.settingsFile.backupAndSave(self.settings)
        else:
            print('[+] Settings have NOT been changed.')

    def getSettings(self):
        return self.settings

    #################### AUXILIARY ####################

    def getCWD(self):
        return self.logic.cwd

    def getProjectName(self):
        return self.logic.projectname

    def getVersion(self):
        return self.version

    def getRunningFolder(self):
        return self.logic.runningfolder

    def getOutputFolder(self):
        return self.logic.outputfolder

    def getUserlistPath(self):
        return self.logic.usernamesWordlist.filename

    def getPasslistPath(self):
        return self.logic.passwordsWordlist.filename

    def updateOutputFolder(self):
        self.screenshooter.updateOutputFolder(
            self.logic.outputfolder+'/screenshots')   # update screenshot folder

    def copyNmapXMLToOutputFolder(self, filename):
        self.logic.copyNmapXMLToOutputFolder(filename)

    def isTempProject(self):
        return self.logic.istemp

    def getDB(self):
        return self.logic.db

    def getRunningProcesses(self):
        return self.processes

    def getHostActions(self):
        return self.settings.hostActions

    def getPortActions(self):
        return self.settings.portActions

    def getPortTerminalActions(self):
        return self.settings.portTerminalActions

    #################### ACTIONS ####################

    def createNewProject(self):
        # removes temp folder (if any)
        self.view.closeProject()
        # creates new temp files and folders
        self.logic.createTemporaryFiles()
        # initialisations (globals, etc)
        self.start()

    def openExistingProject(self, filename):
        self.view.closeProject()
        self.view.importProgressWidget.reset('Opening project..')
        # show the progress widget
        self.view.importProgressWidget.show()
        self.logic.openExistingProject(filename)
        # initialisations (globals, signals, etc)
        self.start(ntpath.basename(str(self.logic.projectname)))
        # restores the tool tabs for each host
        self.view.restoreToolTabs()
        # click on first host to restore his host tool tabs
        self.view.hostTableClick()
        # hide the progress widget
        self.view.importProgressWidget.hide()

    def saveProject(self, lastHostIdClicked, notes):
        if not lastHostIdClicked == '':
            self.logic.storeNotesInDB(lastHostIdClicked, notes)

    def saveProjectAs(self, filename, replace=0):
        success = self.logic.saveProjectAs(filename, replace)
        if success:
            # tell nmap importer which db to use
            self.nmapImporter.setDB(self.logic.db)
        return success

    def closeProject(self):
        # backup and save config file, if necessary
        self.saveSettings()
        self.screenshooter.terminate()
        self.initScreenshooter()
        self.logic.toggleProcessDisplayStatus(True)
        # clear process table
        self.view.updateProcessesTableView()
        self.logic.removeTemporaryFiles()

    def addHosts(self, iprange, runHostDiscovery, runStagedNmap):
        if iprange == '':
            print('[-] No hosts entered..')
            return

        if runStagedNmap:
            self.runStagedNmap(iprange, runHostDiscovery)

        elif runHostDiscovery:
            outputfile = self.logic.runningfolder+"/nmap/"+getTimestamp()+'-host-discover'
            command = "nmap -n -sn -T4 "+iprange+" -oA "+outputfile
            self.runCommand('nmap', 'nmap (discovery)', iprange, '', '', command, getTimestamp(
                True), outputfile, self.view.createNewTabForHost(str(iprange), 'nmap (discovery)', True))

        else:
            outputfile = self.logic.runningfolder+"/nmap/"+getTimestamp()+'-nmap-list'
            command = "nmap -n -sL "+iprange+" -oA "+outputfile
            self.runCommand('nmap', 'nmap (list)', iprange, '', '', command, getTimestamp(
                True), outputfile, self.view.createNewTabForHost(str(iprange), 'nmap (list)', True))

    def importNmap(self, filename):
        if not os.access(filename, os.R_OK):
            raise OSError('[-] Insufficient permissions to read this file.')
            # return

        self.nmapImporter.setFilename(str(filename))
        self.nmapImporter.start()
        self.copyNmapXMLToOutputFolder(str(filename))

    #################### CONTEXT MENUS ####################

    # showAll exists because in some cases we only want to show host tools excluding portscans and 'mark as checked'
    def getContextMenuForHost(self, isChecked, showAll=True):

        menu = QMenu()
        self.nmapSubMenu = QMenu('Portscan')
        actions = []

        for a in self.settings.hostActions:
            if "nmap" in a[1] or "unicornscan" in a[1]:
                actions.append(self.nmapSubMenu.addAction(a[0]))
            else:
                actions.append(menu.addAction(a[0]))

        if showAll:
            actions.append(self.nmapSubMenu.addAction("Run nmap (staged)"))

            menu.addMenu(self.nmapSubMenu)
            menu.addSeparator()

            if isChecked == 'True':
                menu.addAction('Mark as unchecked')
            else:
                menu.addAction('Mark as checked')

        return menu, actions

    def handleHostAction(self, ip, hostid, actions, action):

        if action.text() == 'Mark as checked' or action.text() == 'Mark as unchecked':
            self.logic.toggleHostCheckStatus(ip)
            self.view.updateInterface()
            return

        if action.text() == 'Run nmap (staged)':
            # if we are running nmap we need to purge previous portscan results
            print('[+] Purging previous portscan data for ' + str(ip))
            if self.logic.getPortsForHostFromDB(ip, 'tcp'):
                self.logic.deleteAllPortsAndScriptsForHostFromDB(hostid, 'tcp')
            if self.logic.getPortsForHostFromDB(ip, 'udp'):
                self.logic.deleteAllPortsAndScriptsForHostFromDB(hostid, 'udp')
            self.runStagedNmap(ip, False)
            return

        for i in range(0, len(actions)):
            if action == actions[i]:
                name = self.settings.hostActions[i][1]
                invisibleTab = False
                # to make sure different nmap scans appear under the same tool name
                if 'nmap' in name:
                    name = 'nmap'
                    invisibleTab = True
                    # remove all chars that are not alphanumeric from tool name (used in the outputfile's name)
                outputfile = self.logic.runningfolder+"/"+re.sub("[^0-9a-zA-Z]", "", str(name))+"/"+getTimestamp(
                )+"-"+re.sub("[^0-9a-zA-Z]", "", str(self.settings.hostActions[i][1]))+"-"+ip
                command = str(self.settings.hostActions[i][2])
                command = command.replace('[IP]', ip).replace(
                    '[OUTPUT]', outputfile)
                # check if same type of nmap scan has already been made and purge results before scanning
                if 'nmap' in command:
                    proto = 'tcp'
                    if '-sU' in command:
                        proto = 'udp'

                    # if we are running nmap we need to purge previous portscan results (of the same protocol)
                    if self.logic.getPortsForHostFromDB(ip, proto):
                        self.logic.deleteAllPortsAndScriptsForHostFromDB(
                            hostid, proto)

                tabtitle = self.settings.hostActions[i][1]
                self.runCommand(name, tabtitle, ip, '', '', command, getTimestamp(
                    True), outputfile, self.view.createNewTabForHost(ip, tabtitle, invisibleTab))
                break

    def getContextMenuForServiceName(self, serviceName='*', menu=None):
        if menu == None:                                                # if no menu was given, create a new one
            menu = QMenu()

        if serviceName == '*' or serviceName in self.settings.general_web_services.split(","):
            menu.addAction("Open in browser")
            menu.addAction("Take screenshot")

        actions = []
        for a in self.settings.portActions:
            # if the service name exists in the portActions list show the command in the context menu
            if serviceName is None or serviceName == '*' or serviceName in a[3].split(",") or a[3] == '':
                # in actions list write the service and line number that corresponds to it in portActions
                actions.append(
                    [self.settings.portActions.index(a), menu.addAction(a[0])])

        # if the user pressed SHIFT+Right-click show full menu
        modifiers = QApplication.keyboardModifiers()
        if modifiers == Qt.ShiftModifier:
            shiftPressed = True
        else:
            shiftPressed = False

        return menu, actions, shiftPressed

    def handleServiceNameAction(self, targets, actions, action, restoring=True):

        if action.text() == 'Take screenshot':
            for ip in targets:
                url = ip[0]+':'+ip[1]
                self.screenshooter.addToQueue(url)
            self.screenshooter.start()
            return

        elif action.text() == 'Open in browser':
            for ip in targets:
                url = ip[0]+':'+ip[1]
                self.browser.addToQueue(url)
            self.browser.start()
            return

        for i in range(0, len(actions)):
            if action == actions[i][1]:
                srvc_num = actions[i][0]
                for ip in targets:
                    tool = self.settings.portActions[srvc_num][1]
                    tabtitle = self.settings.portActions[srvc_num][1] + \
                        " ("+ip[1]+"/"+ip[2]+")"
                    outputfile = self.logic.runningfolder+"/" + \
                        re.sub("[^0-9a-zA-Z]", "", str(tool))+"/" + \
                        getTimestamp()+'-'+tool+"-"+ip[0]+"-"+ip[1]

                    command = str(self.settings.portActions[srvc_num][2])
                    command = command.replace('[IP]', ip[0]).replace(
                        '[PORT]', ip[1]).replace('[OUTPUT]', outputfile)

                    if 'nmap' in command and ip[2] == 'udp':
                        command = command.replace("-sV", "-sVU")

                    if 'nmap' in tabtitle:                              # we don't want to show nmap tabs
                        restoring = True

                    self.runCommand(tool, tabtitle, ip[0], ip[1], ip[2], command, getTimestamp(
                        True), outputfile, self.view.createNewTabForHost(ip[0], tabtitle, restoring))
                break

    def getContextMenuForPort(self, serviceName='*'):

        menu = QMenu()

        # if the user pressed SHIFT+Right-click show full menu
        modifiers = QApplication.keyboardModifiers()
        if modifiers == Qt.ShiftModifier:
            serviceName = '*'

        # custom terminal actions from settings file
        terminalActions = []
        # if wildcard or the command is valid for this specific service or if the command is valid for all services
        for a in self.settings.portTerminalActions:
            if serviceName is None or serviceName == '*' or serviceName in a[3].split(",") or a[3] == '':
                terminalActions.append(
                    [self.settings.portTerminalActions.index(a), menu.addAction(a[0])])

        menu.addSeparator()
        menu.addAction("Send to Brute")
        menu.addSeparator()
        # dummy is there because we don't need the third return value
        menu, actions, dummy = self.getContextMenuForServiceName(
            serviceName, menu)

#       menu.addSeparator()
#       menu.addAction("Run custom command")

        return menu, actions, terminalActions

    def handlePortAction(self, targets, actions, terminalActions, action, restoring):

        if action.text() == 'Send to Brute':
            for ip in targets:
                # ip[0] is the IP, ip[1] is the port number and ip[3] is the service name
                self.view.createNewBruteTab(ip[0], ip[1], ip[3])
            return

        if action.text() == 'Run custom command':
            print('custom command')
            return

        # handle terminal actions
        terminal = self.settings.general_default_terminal
        for i in range(0, len(terminalActions)):
            if action == terminalActions[i][1]:
                srvc_num = terminalActions[i][0]
                for ip in targets:
                    command = str(
                        self.settings.portTerminalActions[srvc_num][2])
                    command = command.replace(
                        '[IP]', ip[0]).replace('[PORT]', ip[1])
                    subprocess.Popen(terminal+" -e 'bash -c \"" +
                                     command+"; exec bash\"'", shell=True)
                return

        self.handleServiceNameAction(targets, actions, action, restoring)

    def getContextMenuForProcess(self):
        menu = QMenu()
        # killAction = menu.addAction("Kill")
        # clearAction = menu.addAction("Clear")
        menu.addAction("Kill")
        menu.addAction("Clear")
        return menu

    # selectedProcesses is a list of tuples (pid, status, procId)
    def handleProcessAction(self, selectedProcesses, action):

        if action.text() == 'Kill':
            if self.view.killProcessConfirmation():
                for p in selectedProcesses:
                    if p[1] != "Running":
                        if p[1] == "Waiting":
                            # print("\t[-] Process still waiting to start. Skipping.")
                            if str(self.logic.getProcessStatusForDBId(p[2])) == 'Running':
                                self.killProcess(
                                    self.view.ProcessesTableModel.getProcessPidForId(p[2]), p[2])
                            self.logic.storeProcessCancelStatusInDB(str(p[2]))
                        else:
                            print(
                                "\t[-] This process has already been terminated. Skipping.")
                    else:
                        self.killProcess(p[0], p[2])
                self.view.updateProcessesTableView()
            return

        # hide all the processes that are not running
        if action.text() == 'Clear':
            self.logic.toggleProcessDisplayStatus()
            self.view.updateProcessesTableView()

    #################### LEFT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def isHostInDB(self, host):
        return self.logic.isHostInDB(host)

    def getHostsFromDB(self, filters):
        return self.logic.getHostsFromDB(filters)

    def getServiceNamesFromDB(self, filters):
        return self.logic.getServiceNamesFromDB(filters)

    def getProcessStatusForDBId(self, dbId):
        return self.logic.getProcessStatusForDBId(dbId)

    def getPidForProcess(self, dbId):
        return self.logic.getPidForProcess(dbId)

    def storeCloseTabStatusInDB(self, pid):
        return self.logic.storeCloseTabStatusInDB(pid)

    def getServiceNameForHostAndPort(self, hostIP, port):
        return self.logic.getServiceNameForHostAndPort(hostIP, port)

    #################### RIGHT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def getPortsAndServicesForHostFromDB(self, hostIP, filters):
        return self.logic.getPortsAndServicesForHostFromDB(hostIP, filters)

    def getHostsAndPortsForServiceFromDB(self, serviceName, filters):
        return self.logic.getHostsAndPortsForServiceFromDB(serviceName, filters)

    def getHostInformation(self, hostIP):
        return self.logic.getHostInformation(hostIP)

    def getPortStatesForHost(self, hostid):
        return self.logic.getPortStatesForHost(hostid)

    def getScriptsFromDB(self, hostIP):
        return self.logic.getScriptsFromDB(hostIP)

    def getScriptOutputFromDB(self, scriptDBId):
        return self.logic.getScriptOutputFromDB(scriptDBId)

    def getNoteFromDB(self, hostid):
        return self.logic.getNoteFromDB(hostid)

    def getHostsForTool(self, toolname, closed='False'):
        return self.logic.getHostsForTool(toolname, closed)

    #################### BOTTOM PANEL INTERFACE UPDATE FUNCTIONS ####################

    def getProcessesFromDB(self, filters, showProcesses=''):
        return self.logic.getProcessesFromDB(filters, showProcesses)

    #################### PROCESSES ####################

    def checkProcessQueue(self):
        #       print('# MAX PROCESSES: ' + str(self.settings.general_max_fast_processes))
        #       print('# fast processes running: ' + str(self.fastProcessesRunning))
        #       print('# fast processes queued: ' + str(self.fastProcessQueue.qsize()))
        #       print("[+] Checking process queue..")
        if not self.fastProcessQueue.empty():
            if (self.fastProcessesRunning < int(self.settings.general_max_fast_processes)):
                next_proc = self.fastProcessQueue.get()
                # print(str(next_proc.command))
                if not self.logic.isCanceledProcess(str(next_proc.id)):
                    next_proc.display.clear()
                    self.processes.append(next_proc)
                    self.fastProcessesRunning += 1
                    next_proc.start(next_proc.command)
                    self.logic.storeProcessRunningStatusInDB(
                        next_proc.id, next_proc.pid())
                elif not self.fastProcessQueue.empty():
                    self.checkProcessQueue()
#           else:
#               print('> cannot run processes in the queue')
#       else:
#           print('> queue is empty')

    def cancelProcess(self, dbId):
        print('[+] Canceling process: ' + str(dbId))
        self.logic.storeProcessCancelStatusInDB(
            str(dbId))              # mark it as cancelled
        self.updateUITimer.stop()
        # update the interface soon
        self.updateUITimer.start(1500)

    def killProcess(self, pid, dbId):
        print('[+] Killing process: ' + str(pid))
        self.logic.storeProcessKillStatusInDB(
            str(dbId))                # mark it as killed
        try:
            os.kill(int(pid), signal.SIGTERM)
        except OSError:
            print('\t[-] This process has already been terminated.')
        except:
            print("\t[-] Unexpected error:", sys.exc_info()[0])

    def killRunningProcesses(self):
        print('[+] Killing running processes!')
        for p in self.processes:
            p.finished.disconnect()                 # experimental
            self.killProcess(int(p.pid()), p.id)

    # this function creates a new process, runs the command and takes care of displaying the ouput. returns the PID
    # the last 3 parameters are only used when the command is a staged nmap
    def runCommand(self, name, tabtitle, hostip, port, protocol, command, starttime, outputfile, textbox, discovery=True, stage=0, stop=False):
        print("[DEBUG] Running: " + command)
        # create folder for tool if necessary
        self.logic.createFolderForTool(name)
        qProcess = MyQProcess(name, tabtitle, hostip, port,
                              protocol, command, starttime, outputfile, textbox)
        # database id for the process is stored so that we can retrieve the widget later (in the tools tab)
        textbox.setProperty('dbId', QVariant(
            str(self.logic.addProcessToDB(qProcess))))
        self.fastProcessQueue.put(qProcess)
        qProcess.display.appendPlainText(
            'The process is queued and will start as soon as possible.')
        qProcess.display.appendPlainText(
            'If you want to increase the number of simultaneous processes, change this setting in the configuration file.')
        self.checkProcessQueue()

        # update the processes table
        self.updateUITimer.stop()
        self.updateUITimer.start(900)
        # while the process is running, when there's output to read, display it in the GUI
        qProcess.setProcessChannelMode(QProcess.MergedChannels)
        qProcess.readyReadStandardOutput.connect(lambda: qProcess.display.appendPlainText(
            str(qProcess.readAllStandardOutput().data().decode('ISO-8859-1'))))
        # when the process is finished do this
        qProcess.sigHydra.connect(self.handleHydraFindings)
        qProcess.finished.connect(lambda: self.processFinished(qProcess))
        qProcess.error.connect(lambda: self.processCrashed(qProcess))

        # if this is a staged nmap, launch the next stage
        if stage > 0 and stage < 5:
            qProcess.finished.connect(lambda: self.runStagedNmap(
                str(hostip), discovery, stage+1, self.logic.isKilledProcess(str(qProcess.id))))

        # return the pid so that we can kill the process if needed
        return qProcess.pid()

    # recursive function used to run nmap in different stages for quick results
    def runStagedNmap(self, iprange, discovery=True, stage=1, stop=False):

        if not stop:
            textbox = self.view.createNewTabForHost(
                str(iprange), 'nmap (stage '+str(stage)+')', True)
            outputfile = self.logic.runningfolder+"/nmap/" + \
                getTimestamp()+'-nmapstage'+str(stage)

            if stage == 1:                                              # webservers/proxies
                ports = self.settings.tools_nmap_stage1_ports
            elif stage == 2:                                            # juicy stuff that we could enumerate + db
                ports = self.settings.tools_nmap_stage2_ports
            elif stage == 3:                                            # bruteforceable protocols + portmapper + nfs
                ports = self.settings.tools_nmap_stage3_ports
            elif stage == 4:                                            # first 30000 ports except ones above
                ports = self.settings.tools_nmap_stage4_ports
            else:                                                       # last 35535 ports
                ports = self.settings.tools_nmap_stage5_ports

            command = "nmap "
            if not discovery:                                           # is it with/without host discovery?
                command += "-Pn "
            # without scripts (faster)
            command += "-T4 -sV "
            if not stage == 1:
                # only do DNS resolution on first stage
                command += "-n "
            if os.geteuid() == 0:                                       # if we are root we can run SYN + UDP scans
                command += "-sSU "
                if stage == 2:
                    # only check for OS once to save time and only if we are root otherwise it fails
                    command += "-O "
            else:
                command += "-sT "
            command += "-p "+ports+' '+iprange+" -oA "+outputfile

            self.runCommand('nmap', 'nmap (stage '+str(stage)+')', str(iprange), '', '',
                            command, getTimestamp(True), outputfile, textbox, discovery, stage, stop)

    def nmapImportFinished(self):
        self.updateUI2Timer.stop()
        self.updateUI2Timer.start(800)
        # hide the progress widget
        self.view.importProgressWidget.hide()
        # if nmap import was the first action, we need to hide the overlay (note: we shouldn't need to do this everytime. this can be improved)
        self.view.displayAddHostsOverlay(False)

    def screenshotFinished(self, ip, port, filename):
        dbId = self.logic.addScreenshotToDB(str(ip), str(port), str(filename))
        imageviewer = self.view.createNewTabForHost(
            ip, 'screenshot ('+port+'/tcp)', True, '', str(self.logic.outputfolder)+'/screenshots/'+str(filename))
        imageviewer.setProperty('dbId', QVariant(str(dbId)))
        # to make sure the screenshot tab appears when it is launched from the host services tab
        self.view.switchTabClick()
        # update the processes table
        self.updateUITimer.stop()
        self.updateUITimer.start(900)

    def processCrashed(self, proc):
        # self.processFinished(proc, True)
        self.logic.storeProcessCrashStatusInDB(str(proc.id))
        print('[+] Process killed!')

    # this function handles everything after a process ends
    # def processFinished(self, qProcess, crashed=False):
    def processFinished(self, qProcess):
        # print('processFinished!!')
        try:
            # if process was not killed
            if not self.logic.isKilledProcess(str(qProcess.id)):
                if not qProcess.outputfile == '':
                    # move tool output from runningfolder to output folder if there was an output file
                    self.logic.moveToolOutput(qProcess.outputfile)

                    if 'nmap' in qProcess.name:                         # if the process was nmap, use the parser to store it
                        if qProcess.exitCode() == 0:                    # if the process finished successfully
                            newoutputfile = qProcess.outputfile.replace(
                                self.logic.runningfolder, self.logic.outputfolder)
                            self.nmapImporter.setFilename(
                                str(newoutputfile)+'.xml')
                            self.view.importProgressWidget.reset(
                                'Importing nmap..')
                            self.nmapImporter.setOutput(
                                str(qProcess.display.toPlainText()))
                            self.nmapImporter.start()
                            if self.view.menuVisible == False:
                                self.view.importProgressWidget.show()

                print("\t[+] The process is done!")

            self.logic.storeProcessOutputInDB(
                str(qProcess.id), qProcess.display.toPlainText())

            # find the corresponding widget and tell it to update its UI
            if 'hydra' in qProcess.name:
                self.view.findFinishedBruteTab(
                    str(self.logic.getPidForProcess(str(qProcess.id))))

            try:
                self.fastProcessesRunning -= 1
                self.checkProcessQueue()
                self.processes.remove(qProcess)
                self.updateUITimer.stop()
                # update the interface soon
                self.updateUITimer.start(1500)

            except ValueError:
                pass
        # fixes bug when receiving finished signal when project is no longer open.
        except:
            pass

    # when hydra finds valid credentials we need to save them and change the brute tab title to red
    def handleHydraFindings(self, bWidget, userlist, passlist):
        self.view.blinkBruteTab(bWidget)
        for username in userlist:
            self.logic.usernamesWordlist.add(username)
        for password in passlist:
            self.logic.passwordsWordlist.add(password)

    # this function parses nmap's output looking for open ports to run automated attacks on
    def scheduler(self, parser, isNmapImport):
        if isNmapImport and self.settings.general_enable_scheduler_on_import == 'False':
            return
        if self.settings.general_enable_scheduler == 'True':
            print('[+] Scheduler started!')

            for h in parser.all_hosts():
                for p in h.all_ports():
                    if p.state == 'open':
                        s = p.get_service()
                        if not (s is None):
                            self.runToolsFor(
                                s.name, h.ip, p.portId, p.protocol)

            print('-----------------------------------------------')
        print('[+] Scheduler ended!')

    def runToolsFor(self, service, ip, port, protocol='tcp'):
        print('\t[+] Running tools for: ' + service + ' on ' + ip + ':' + port)

        # when nmap is not sure it will append a ?, so we need to remove it
        if service.endswith("?"):
            service = service[:-1]

        for tool in self.settings.automatedAttacks:
            if service in tool[1].split(",") and protocol == tool[2]:
                if tool[0] == "screenshooter":
                    url = ip+':'+port
                    self.screenshooter.addToQueue(url)
                    self.screenshooter.start()

                else:
                    for a in self.settings.portActions:
                        if tool[0] == a[1]:
                            # restoring = False
                            tabtitle = a[1]+" ("+port+"/"+protocol+")"
                            outputfile = self.logic.runningfolder+"/" + \
                                re.sub("[^0-9a-zA-Z]", "", str(tool[0])) + \
                                "/"+getTimestamp()+'-'+a[1]+"-"+ip+"-"+port
                            command = str(a[2])
                            command = command.replace('[IP]', ip).replace(
                                '[PORT]', port).replace('[OUTPUT]', outputfile)

                            # if 'nmap' in tabtitle:                          # we don't want to show nmap tabs
                            #    restoring = True

                            tab = self.view.ui.HostsTabWidget.tabText(
                                self.view.ui.HostsTabWidget.currentIndex())
                            self.runCommand(tool[0], tabtitle, ip, port, protocol, command, getTimestamp(
                                True), outputfile, self.view.createNewTabForHost(ip, tabtitle, not (tab == 'Hosts')))
                            break
