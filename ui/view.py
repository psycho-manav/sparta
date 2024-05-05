#!/usr/bin/env python

'''
SPARTA - Network Infrastructure Penetration Testing Tool (http://sparta.secforce.com)
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
import time
import webbrowser
from PyQt5.QtGui import QColor, QPalette
from PyQt5.QtCore import QVariant, QObject, pyqtSignal, Qt
from PyQt5.QtWidgets import QTabBar, QMenu, QMessageBox, QFileDialog, QPlainTextEdit, QWidget, QHBoxLayout
# from ui.gui import *
from ui.dialogs import HostInformationWidget, FiltersDialog, ProgressWidget, AddHostsDialog, ImagePlayer, ImageViewer, BruteWidget
# from ui.settingsdialogs import *
from app.hostmodels import HostsTableModel
from app.servicemodels import ServicesTableModel, ServiceNamesTableModel
from app.scriptmodels import ScriptsTableModel
from app.processmodels import ProcessesTableModel
from app.auxiliary import Filters, setTableProperties, validateNmapInput, validateCredentials, getTimestamp


# this class handles everything gui-related
class View(QObject):
    # signal used to update the progress bar
    tick = pyqtSignal(int, name="changed")

    def __init__(self, ui, ui_mainwindow):
        QObject.__init__(self)
        self.ui = ui
        # TODO: retrieve window dimensions/location from settings
        self.ui_mainwindow = ui_mainwindow
        # align window to topleft corner and set default size
        self.ui_mainwindow.setGeometry(0, 30, 1024, 650)
        # set better default size for bottom panel
        self.ui.splitter_2.setSizes([300, 10])
        # initialisations that happen only once, when the SPARTA is launched
        self.startOnce()
        # signal initialisations (signals/slots, actions, etc)
        self.startConnections()

    # the view needs access to controller methods to link gui actions with real actions
    def setController(self, controller):
        self.controller = controller

    def startOnce(self):
        # the number of fixed host tabs (services, scripts, information, notes)
        self.fixedTabsCount = self.ui.ServicesTabWidget.count()
        self.hostInfoWidget = HostInformationWidget(self.ui.InformationTab)
        self.filterdialog = FiltersDialog(self.ui.centralwidget)
        self.importProgressWidget = ProgressWidget(
            'Importing nmap..', self.ui.centralwidget)
        self.adddialog = AddHostsDialog(self.ui.centralwidget)
        # self.settingsWidget = AddSettingsDialog(self.ui.centralwidget)

        # kali moves the help file so let's find it
        self.helpurl = './doc/help.html'
        if not os.path.exists(self.helpurl):
            self.helpurl = '/usr/share/doc/sparta/help.html'

        # disable multiple selection
        self.ui.HostsTableView.setSelectionMode(1)
        self.ui.ServiceNamesTableView.setSelectionMode(1)
        self.ui.ToolsTableView.setSelectionMode(1)
        self.ui.ScriptsTableView.setSelectionMode(1)
        self.ui.ToolHostsTableView.setSelectionMode(1)

    # initialisations (globals, etc)
    def start(self, title='*untitled'):
        # to know if the project has been saved
        self.dirty = False
        # to know if we should use the save as dialog (should probably be False until we add/import a host)
        self.firstSave = True
        # to keep track of which tabs should be displayed for each host
        self.hostTabs = dict()
        # to keep track of the numbering of the bruteforce tabs (incremented when a new tab is added)
        self.bruteTabCount = 1

        # to choose what to display in each panel
        self.filters = Filters()

        # clear keyword filter
        self.ui.keywordTextInput.setText('')

        # TODO: check if we can get rid of this one.
        self.lastHostIdClicked = ''
        # useful when updating interfaces (serves as memory)
        self.ip_clicked = ''
        # useful when updating interfaces (serves as memory)
        self.service_clicked = ''
        # useful when updating interfaces (serves as memory)
        self.tool_clicked = ''
        # useful when updating interfaces (serves as memory)
        self.script_clicked = ''
        # useful when updating interfaces (serves as memory)
        self.tool_host_clicked = ''
        # these variables indicate that the corresponding table needs to be updated.
        self.lazy_update_hosts = False
        # 'lazy' means we only update a table at the last possible minute - before the user needs to see it
        self.lazy_update_services = False
        self.lazy_update_tools = False
        # to know if a context menu is showing (important to avoid disrupting the user)
        self.menuVisible = False
        # fixes bug when sorting processes for the first time
        self.ProcessesTableModel = None

        self.setMainWindowTitle(title)
        self.ui.statusbar.showMessage('Starting up..', msecs=1000)

        # initialise all tables
        self.initTables()

        self.updateInterface()
        # True means we want to show the original textedit
        self.restoreToolTabWidget(True)
        # update the script output panel (right)
        self.updateScriptsOutputView('')
        self.updateToolHostsTableView('')
        # display scan tab by default
        self.ui.MainTabWidget.setCurrentIndex(0)
        # display Hosts tab by default
        self.ui.HostsTabWidget.setCurrentIndex(0)
        # display Services tab by default
        self.ui.ServicesTabWidget.setCurrentIndex(0)
        # display Log tab by default
        self.ui.BottomTabWidget.setCurrentIndex(0)
        # sets all tabs as closable in bruteforcer
        self.ui.BruteTabWidget.setTabsClosable(True)

        # hide the close button (cross) from the fixed tabs
        self.ui.ServicesTabWidget.setTabsClosable(True)

        self.ui.ServicesTabWidget.tabBar().setTabButton(0, QTabBar.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(1, QTabBar.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(2, QTabBar.RightSide, None)
        self.ui.ServicesTabWidget.tabBar().setTabButton(3, QTabBar.RightSide, None)

        # clear brute tabs (if any) and create default brute tab
        self.resetBruteTabs()
        self.displayToolPanel(False)
        self.displayScreenshots(False)
        # displays an overlay over the hosttableview saying 'click here to add host(s) to scope'
        self.displayAddHostsOverlay(True)

    # signal initialisations (signals/slots, actions, etc)
    def startConnections(self):
        ### MENU ACTIONS ###
        self.connectCreateNewProject()
        self.connectOpenExistingProject()
        self.connectSaveProject()
        self.connectSaveProjectAs()
        self.connectAddHosts()
        self.connectImportNmap()
        # self.connectSettings()
        self.connectHelp()
        self.connectAppExit()
        ### TABLE ACTIONS ###
        self.connectAddHostsOverlayClick()
        self.connectHostTableClick()
        self.connectServiceNamesTableClick()
        self.connectToolsTableClick()
        self.connectScriptTableClick()
        self.connectToolHostsClick()
        self.connectAdvancedFilterClick()
        # to detect changing tabs (on left panel)
        self.connectSwitchTabClick()
        # to detect changing top level tabs
        self.connectSwitchMainTabClick()
        # for double clicking on host (it redirects to the host view)
        self.connectTableDoubleClick()
        ### CONTEXT MENUS ###
        self.connectHostsTableContextMenu()
        self.connectServiceNamesTableContextMenu()
        self.connectServicesTableContextMenu()
        self.connectToolHostsTableContextMenu()
        self.connectProcessesTableContextMenu()
        self.connectScreenshotContextMenu()
        ### OTHER ###
        self.ui.NotesTextEdit.textChanged.connect(self.setDirty)
        self.ui.FilterApplyButton.clicked.connect(self.updateFilterKeywords)
        self.ui.ServicesTabWidget.tabCloseRequested.connect(
            self.closeHostToolTab)
        self.ui.BruteTabWidget.tabCloseRequested.connect(self.closeBruteTab)
        self.ui.keywordTextInput.returnPressed.connect(
            self.ui.FilterApplyButton.click)
        self.filterdialog.applyButton.clicked.connect(self.updateFilter)
#        self.settingsWidget.applyButton.clicked.connect(self.applySettings)
#        self.settingsWidget.cancelButton.clicked.connect(self.cancelSettings)
        # self.settingsWidget.applyButton.clicked.connect(self.controller.applySettings(self.settingsWidget.settings))
        # slot used to update the progress bar
        self.tick.connect(self.importProgressWidget.setProgress)

    #################### AUXILIARY ####################

    # this function prepares the default settings for each table
    def initTables(self):
        # hosts table (left)
        headers = ["Id", "OS", "Accuracy", "Host", "IPv4", "IPv6", "Mac", "Status", "Hostname",
                   "Vendor", "Uptime", "Lastboot", "Distance", "CheckedHost", "State", "Count"]
        setTableProperties(self.ui.HostsTableView, len(headers), [
                           0, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        # self.ui.HostsTableView.horizontalHeader().setResizeMode(1,2)
        self.ui.HostsTableView.horizontalHeader().resizeSection(1, 30)

        # service names table (left)
        headers = ["Name"]
        setTableProperties(self.ui.ServiceNamesTableView, len(headers))

        # tools table (left)
        headers = ["Progress", "Display", "Pid", "Tool", "Tool", "Host", "Port",
                   "Protocol", "Command", "Start time", "OutputFile", "Output", "Status"]
        setTableProperties(self.ui.ToolsTableView, len(headers), [
                           0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13])

        # service table (right)
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId",
                   "ServiceId", "Name", "Product", "Version", "Extrainfo", "Fingerprint"]
        setTableProperties(self.ui.ServicesTableView,
                           len(headers), [0, 1, 5, 6, 8, 10, 11])
        # self.ui.ServicesTableView.horizontalHeader().setResizeMode(0)

        # ports by service (right)
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId",
                   "ServiceId", "Name", "Product", "Version", "Extrainfo", "Fingerprint"]
        setTableProperties(self.ui.ServicesTableView,
                           len(headers), [2, 5, 6, 8, 10, 11])
        # self.ui.ServicesTableView.horizontalHeader().setResizeMode(0)
        self.ui.ServicesTableView.horizontalHeader().resizeSection(0, 130)       # resize IP

        # scripts table (right)
        headers = ["Id", "Script", "Port", "Protocol"]
        setTableProperties(self.ui.ScriptsTableView, len(headers), [0, 3])

        # tool hosts table (right)
        headers = ["Progress", "Display", "Pid", "Name", "Action", "Target", "Port",
                   "Protocol", "Command", "Start time", "OutputFile", "Output", "Status"]
        setTableProperties(self.ui.ToolHostsTableView, len(
            headers), [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12])
        self.ui.ToolHostsTableView.horizontalHeader().resizeSection(
            5, 150)      # default width for Host column

        # process table
        headers = ["Progress", "Display", "Pid", "Name", "Tool", "Host", "Port",
                   "Protocol", "Command", "Start time", "OutputFile", "Output", "Status"]
        # setTableProperties(self.ui.ProcessesTableView, len(headers), [1,2,3,6,7,8,10,11])
        setTableProperties(self.ui.ProcessesTableView, len(
            headers), [1, 2, 3, 6, 7, 8, 11, 12, 14])
        self.ui.ProcessesTableView.horizontalHeader().resizeSection(0, 125)
        # self.ui.ProcessesTableView.horizontalHeader().resizeSection(4,125)
        self.ui.ProcessesTableView.horizontalHeader().resizeSection(4, 250)

    def setMainWindowTitle(self, title):
        self.ui_mainwindow.setWindowTitle(str(title))

    # this function is called for example when the user edits notes
    def setDirty(self, status=True):
        self.dirty = status
        title = ''

        if self.dirty:
            title = '*'
        if self.controller.isTempProject():
            title += 'untitled'
        else:
            title += ntpath.basename(str(self.controller.getProjectName()))

        self.setMainWindowTitle(self.controller.getVersion(
        ) + ' - ' + title + ' - ' + self.controller.getCWD())

    #################### ACTIONS ####################

    def dealWithRunningProcesses(self, exiting=False):
        if len(self.controller.getRunningProcesses()) > 0:
            message = "There are still processes running. If you continue, every process will be terminated. Are you sure you want to continue?"
            reply = QMessageBox.question(
                self.ui.centralwidget, 'Confirm', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)

            if not reply == QMessageBox.Yes:
                return False
            self.controller.killRunningProcesses()

        elif exiting:
            return self.confirmExit()

        return True

    # returns True if we can proceed with: creating/opening a project or exiting
    def dealWithCurrentProject(self, exiting=False):
        # if there are unsaved changes, show save dialog first
        if self.dirty:
            if not self.saveOrDiscard():                                # if the user canceled, stop
                return False

        # deal with running processes
        return self.dealWithRunningProcesses(exiting)

    def confirmExit(self):
        reply = QMessageBox.question(self.ui.centralwidget, 'Confirm',
                                     "Are you sure to exit the program?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        return (reply == QMessageBox.Yes)

    def killProcessConfirmation(self):
        message = "Are you sure you want to kill the selected processes?"
        reply = QMessageBox.question(
            self.ui.centralwidget, 'Confirm', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            return True
        return False

    ###

    def connectCreateNewProject(self):
        self.ui.actionNew.triggered.connect(self.createNewProject)

    def createNewProject(self):
        if self.dealWithCurrentProject():
            print('[+] Creating new project..')
            self.controller.createNewProject()

    ###

    def connectOpenExistingProject(self):
        self.ui.actionOpen.triggered.connect(self.openExistingProject)

    def openExistingProject(self):
        if self.dealWithCurrentProject():
            filename = QFileDialog.getOpenFileName(
                self.ui.centralwidget, 'Open project', self.controller.getCWD(), filter='SPARTA project (*.sprt)')[0]

            if not filename == '':                                      # check for permissions
                if not os.access(filename, os.R_OK) or not os.access(filename, os.W_OK):
                    print('[-] Insufficient permissions to open this file.')
                    # reply = QMessageBox.warning(self.ui.centralwidget, 'Warning', "You don't have the necessary permissions on this file.","Ok")
                    QMessageBox.warning(self.ui.centralwidget, 'Warning',
                                        "You don't have the necessary permissions on this file.", "Ok")
                    return

                self.controller.openExistingProject(filename)
                # overwrite this variable because we are opening an existing file
                self.firstSave = False
                # do not show the overlay because the hosttableview is already populated
                self.displayAddHostsOverlay(False)

            else:
                print('\t[-] No file chosen..')

    ###

    def connectSaveProject(self):
        self.ui.actionSave.triggered.connect(self.saveProject)

    def saveProject(self):
        self.ui.statusbar.showMessage('Saving..')
        if self.firstSave:
            self.saveProjectAs()
        else:
            print('[+] Saving project..')
            self.controller.saveProject(
                self.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())

            self.setDirty(False)
            self.ui.statusbar.showMessage('Saved!', msecs=1000)
            print('\t[+] Saved!')

    ###

    def connectSaveProjectAs(self):
        self.ui.actionSaveAs.triggered.connect(self.saveProjectAs)

    def saveProjectAs(self):
        self.ui.statusbar.showMessage('Saving..')
        print('[+] Saving project..')

        self.controller.saveProject(
            self.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())

        filename = QFileDialog.getSaveFileName(self.ui.centralwidget, 'Save project as', self.controller.getCWD(
        ), filter='SPARTA project (*.sprt)', options=QFileDialog.DontConfirmOverwrite)[0]

        while not filename == '':

            if not os.access(ntpath.dirname(str(filename)), os.R_OK) or not os.access(ntpath.dirname(str(filename)), os.W_OK):
                print('[-] Insufficient permissions on this folder.')
                reply = QMessageBox.warning(
                    self.ui.centralwidget, 'Warning', "You don't have the necessary permissions on this folder.")

            else:
                if self.controller.saveProjectAs(filename):
                    break

                if not str(filename).endswith('.sprt'):
                    filename = str(filename) + '.sprt'
                msgBox = QMessageBox()
                reply = msgBox.question(self.ui.centralwidget, 'Confirm', "A file named \""+ntpath.basename(str(
                    filename))+"\" already exists.  Do you want to replace it?", QMessageBox.Abort | QMessageBox.Save)

                if reply == QMessageBox.Save:
                    self.controller.saveProjectAs(
                        filename, 1)          # replace
                    break

            filename = QFileDialog.getSaveFileName(
                self.ui.centralwidget, 'Save project as', '.', filter='SPARTA project (*.sprt)', options=QFileDialog.DontConfirmOverwrite)[0]

        if not filename == '':
            self.setDirty(False)
            self.firstSave = False
            self.ui.statusbar.showMessage('Saved!', msecs=1000)
            self.controller.updateOutputFolder()
            print('\t[+] Saved!')
        else:
            print('\t[-] No file chosen..')

    ###

    def saveOrDiscard(self):
        reply = QMessageBox.question(self.ui.centralwidget, 'Confirm', "The project has been modified. Do you want to save your changes?",
                                     QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel, QMessageBox.Save)

        if reply == QMessageBox.Save:
            self.saveProject()
            return True
        elif reply == QMessageBox.Discard:
            return True
        else:
            return False                                                # the user cancelled

    ###

    def closeProject(self):
        self.ui.statusbar.showMessage('Closing project..', msecs=1000)
        self.controller.closeProject()
        # to make them disappear from the UI
        self.removeToolTabs()

    ###

    def connectAddHosts(self):
        self.ui.actionAddHosts.triggered.connect(self.connectAddHostsDialog)

    def connectAddHostsDialog(self):
        self.adddialog.addButton.setDefault(True)
        self.adddialog.textinput.setFocus(True)
        self.adddialog.validationLabel.hide()
        self.adddialog.spacer.changeSize(15, 15)
        self.adddialog.show()
        self.adddialog.addButton.clicked.connect(self.callAddHosts)
        self.adddialog.cancelButton.clicked.connect(self.adddialog.close)

    def callAddHosts(self):
        if validateNmapInput(self.adddialog.textinput.text()):
            self.adddialog.close()
            self.controller.addHosts(self.adddialog.textinput.text(
            ), self.adddialog.discovery.isChecked(), self.adddialog.nmap.isChecked())
            # disconnect all the signals from that button
            self.adddialog.addButton.clicked.disconnect()
        else:
            self.adddialog.spacer.changeSize(0, 0)
            self.adddialog.validationLabel.show()
            # disconnect all the signals from that button
            self.adddialog.addButton.clicked.disconnect()
            self.adddialog.addButton.clicked.connect(self.callAddHosts)

    ###

    def connectImportNmap(self):
        self.ui.actionImportNmap.triggered.connect(self.importNmap)

    def importNmap(self):
        self.ui.statusbar.showMessage('Importing nmap xml..', msecs=1000)
        filename = QFileDialog.getOpenFileName(
            self.ui.centralwidget, 'Choose nmap file', self.controller.getCWD(), filter='XML file (*.xml)')[0]

        if not filename == '':

            # check for read permissions on the xml file
            if not os.access(filename, os.R_OK):
                print('[-] Insufficient permissions to read this file.')
                # reply = QMessageBox.warning(self.ui.centralwidget, 'Warning', "You don't have the necessary permissions to read this file.","Ok")
                QMessageBox.warning(self.ui.centralwidget, 'Warning',
                                    "You don't have the necessary permissions to read this file.", "Ok")
                return

            self.importProgressWidget.reset('Importing nmap..')
            self.controller.nmapImporter.setFilename(str(filename))
            self.controller.nmapImporter.start()
            self.controller.copyNmapXMLToOutputFolder(str(filename))
            self.importProgressWidget.show()

        else:
            print('\t[-] No file chosen..')

    ###

#    def connectSettings(self):
#        self.ui.actionSettings.triggered.connect(self.showSettingsWidget)

#    def showSettingsWidget(self):
#        self.settingsWidget.resetTabIndexes()
#        self.settingsWidget.show()

#    def applySettings(self):
#        if self.settingsWidget.applySettings():
#            self.controller.applySettings(self.settingsWidget.settings)
#            self.settingsWidget.hide()

#    def cancelSettings(self):
#        print('DEBUG: cancel button pressed')                           # LEO: we can use this later to test ESC button once implemented.
#        self.settingsWidget.hide()
#        self.controller.cancelSettings()

    def connectHelp(self):
        self.ui.menuHelp.triggered.connect(self.showHelp)

    def showHelp(self):
        webbrowser.open(self.helpurl)

    ###

    def connectAppExit(self):
        self.ui.actionExit.triggered.connect(self.appExit)

    def appExit(self):
        # the parameter indicates that we are exiting the application
        if self.dealWithCurrentProject(True):
            self.closeProject()
            print('[+] Exiting application..')
            # os._exit(0)
            # del(self.ui)
            sys.exit(0)

    ### TABLE ACTIONS ###

    def connectAddHostsOverlayClick(self):
        self.ui.addHostsOverlay.selectionChanged.connect(
            self.connectAddHostsDialog)

    def connectHostTableClick(self):
        self.ui.HostsTableView.clicked.connect(self.hostTableClick)

    # TODO: review - especially what tab is selected when coming from another host
    def hostTableClick(self):
        # get the IP address of the selected host (if any)
        if self.ui.HostsTableView.selectionModel().selectedRows():
            row = self.ui.HostsTableView.selectionModel().selectedRows()[len(
                self.ui.HostsTableView.selectionModel().selectedRows())-1].row()
            self.ip_clicked = self.HostsTableModel.getHostIPForRow(row)
            save = self.ui.ServicesTabWidget.currentIndex()
            self.removeToolTabs()
            self.restoreToolTabsForHost(self.ip_clicked)
            self.updateRightPanel(self.ip_clicked)
            # display services tab if we are coming from a dynamic tab (non-fixed)
            self.ui.ServicesTabWidget.setCurrentIndex(save)

        else:
            self.removeToolTabs()
            self.updateRightPanel('')

    ###

    def connectServiceNamesTableClick(self):
        self.ui.ServiceNamesTableView.clicked.connect(
            self.serviceNamesTableClick)

    def serviceNamesTableClick(self):
        if self.ui.ServiceNamesTableView.selectionModel().selectedRows():
            row = self.ui.ServiceNamesTableView.selectionModel().selectedRows()[len(
                self.ui.ServiceNamesTableView.selectionModel().selectedRows())-1].row()
            self.service_clicked = self.ServiceNamesTableModel.getServiceNameForRow(
                row)
            self.updatePortsByServiceTableView(self.service_clicked)

    ###

    def connectToolsTableClick(self):
        self.ui.ToolsTableView.clicked.connect(self.toolsTableClick)

    def toolsTableClick(self):
        if self.ui.ToolsTableView.selectionModel().selectedRows():
            row = self.ui.ToolsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolsTableView.selectionModel().selectedRows())-1].row()
            self.tool_clicked = self.ToolsTableModel.getToolNameForRow(row)
            self.updateToolHostsTableView(self.tool_clicked)
            # if we clicked on the screenshooter we need to display the screenshot widget
            self.displayScreenshots(self.tool_clicked == 'screenshooter')

        # update the updateToolHostsTableView when the user closes all the host tabs
        # TODO: this doesn't seem right
        else:
            self.updateToolHostsTableView('')
            self.ui.DisplayWidgetLayout.addWidget(self.ui.toolOutputTextView)

    ###

    def connectScriptTableClick(self):
        self.ui.ScriptsTableView.clicked.connect(self.scriptTableClick)

    def scriptTableClick(self):
        if self.ui.ScriptsTableView.selectionModel().selectedRows():
            row = self.ui.ScriptsTableView.selectionModel().selectedRows()[len(
                self.ui.ScriptsTableView.selectionModel().selectedRows())-1].row()
            self.script_clicked = self.ScriptsTableModel.getScriptDBIdForRow(
                row)
            self.updateScriptsOutputView(self.script_clicked)

    ###

    def connectToolHostsClick(self):
        self.ui.ToolHostsTableView.clicked.connect(self.toolHostsClick)

    # TODO: review / duplicate code
    def toolHostsClick(self):
        if self.ui.ToolHostsTableView.selectionModel().selectedRows():
            row = self.ui.ToolHostsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolHostsTableView.selectionModel().selectedRows())-1].row()
            self.tool_host_clicked = self.ToolHostsTableModel.getProcessIdForRow(
                row)
            ip = self.ToolHostsTableModel.getIpForRow(row)

            if self.tool_clicked == 'screenshooter':
                filename = self.ToolHostsTableModel.getOutputfileForRow(row)
                self.ui.ScreenshotWidget.open(
                    str(self.controller.getOutputFolder())+'/screenshots/'+str(filename))

            else:
                # restore the tool output textview now showing in the tools display panel to its original host tool tab
                self.restoreToolTabWidget()

                # remove the tool output currently in the tools display panel (if any)
                if self.ui.DisplayWidget.findChild(QPlainTextEdit):
                    self.ui.DisplayWidget.findChild(
                        QPlainTextEdit).setParent(None)

                # fetch tab list for this host (if any)
                tabs = []
                if str(ip) in self.hostTabs:
                    tabs = self.hostTabs[str(ip)]

                # place the tool output textview in the tools display panel
                for tab in tabs:
                    if tab.findChild(QPlainTextEdit) and str(tab.findChild(QPlainTextEdit).property('dbId')) == str(self.tool_host_clicked):
                        self.ui.DisplayWidgetLayout.addWidget(
                            tab.findChild(QPlainTextEdit))
                        break

    ###

    def connectAdvancedFilterClick(self):
        self.ui.FilterAdvancedButton.clicked.connect(self.advancedFilterClick)

    def advancedFilterClick(self, current):
        # to make sure we don't show filters than have been clicked but cancelled
        self.filterdialog.setCurrentFilters(self.filters.getFilters())
        self.filterdialog.show()

    def updateFilter(self):
        f = self.filterdialog.getFilters()
        self.filters.apply(f[0], f[1], f[2], f[3],
                           f[4], f[5], f[6], f[7], f[8])
        self.ui.keywordTextInput.setText(" ".join(f[8]))
        self.updateInterface()

    def updateFilterKeywords(self):
        self.filters.setKeywords(str(self.ui.keywordTextInput.text()).split())
        self.updateInterface()

    ###

    def connectTableDoubleClick(self):
        self.ui.ServicesTableView.doubleClicked.connect(self.tableDoubleClick)
        self.ui.ToolHostsTableView.doubleClicked.connect(self.tableDoubleClick)

    def tableDoubleClick(self):
        tab = self.ui.HostsTabWidget.tabText(
            self.ui.HostsTabWidget.currentIndex())

        if tab == 'Services':
            row = self.ui.ServicesTableView.selectionModel().selectedRows()[len(
                self.ui.ServicesTableView.selectionModel().selectedRows())-1].row()
            ip = self.PortsByServiceTableModel.getIpForRow(row)
        elif tab == 'Tools':
            row = self.ui.ToolHostsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolHostsTableView.selectionModel().selectedRows())-1].row()
            ip = self.ToolHostsTableModel.getIpForRow(row)
        else:
            return

        hostrow = self.HostsTableModel.getRowForIp(ip)
        if hostrow is not None:
            self.ui.HostsTabWidget.setCurrentIndex(0)
            self.ui.HostsTableView.selectRow(hostrow)
            self.hostTableClick()

    ###

    def connectSwitchTabClick(self):
        self.ui.HostsTabWidget.currentChanged.connect(self.switchTabClick)

    def switchTabClick(self):
        if self.ServiceNamesTableModel:                                 # fixes bug when switching tabs at start-up
            selectedTab = self.ui.HostsTabWidget.tabText(
                self.ui.HostsTabWidget.currentIndex())

            if selectedTab == 'Hosts':
                self.ui.ServicesTabWidget.insertTab(
                    1, self.ui.ScriptsTab, ("Scripts"))
                self.ui.ServicesTabWidget.insertTab(
                    2, self.ui.InformationTab, ("Information"))
                self.ui.ServicesTabWidget.insertTab(
                    3, self.ui.NotesTab, ("Notes"))
                self.ui.ServicesTabWidget.tabBar().setTabButton(0, QTabBar.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(1, QTabBar.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(2, QTabBar.RightSide, None)
                self.ui.ServicesTabWidget.tabBar().setTabButton(3, QTabBar.RightSide, None)

                self.restoreToolTabWidget()
                ###
                if self.lazy_update_hosts == True:
                    self.updateHostsTableView()
                ###
                self.hostTableClick()

            elif selectedTab == 'Services':
                self.ui.ServicesTabWidget.setCurrentIndex(0)
                # remove the tool tabs
                self.removeToolTabs(0)
                self.controller.saveProject(
                    self.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())
                if self.lazy_update_services == True:
                    self.updateServiceNamesTableView()
                self.serviceNamesTableClick()

            elif selectedTab == 'Tools':
                self.updateToolsTableView()

            # display tool panel if we are in tools tab, hide it otherwise
            self.displayToolPanel(selectedTab == 'Tools')

    ###

    def connectSwitchMainTabClick(self):
        self.ui.MainTabWidget.currentChanged.connect(self.switchMainTabClick)

    def switchMainTabClick(self):
        selectedTab = self.ui.MainTabWidget.tabText(
            self.ui.MainTabWidget.currentIndex())

        if selectedTab == 'Scan':
            self.switchTabClick()

        elif selectedTab == 'Brute':
            self.ui.BruteTabWidget.currentWidget().runButton.setFocus()
            self.restoreToolTabWidget()

        # in case the Brute tab was red because hydra found stuff, change it back to black
        self.ui.MainTabWidget.tabBar().setTabTextColor(1, QColor())

    ###
    # indicates that a context menu is showing so that the ui doesn't get updated disrupting the user
    def setVisible(self):
        self.menuVisible = True

    # indicates that a context menu has now closed and any pending ui updates can take place now
    def setInvisible(self):
        self.menuVisible = False
    ###

    def connectHostsTableContextMenu(self):
        self.ui.HostsTableView.customContextMenuRequested.connect(
            self.contextMenuHostsTableView)

    def contextMenuHostsTableView(self, pos):
        if len(self.ui.HostsTableView.selectionModel().selectedRows()) > 0:
            row = self.ui.HostsTableView.selectionModel().selectedRows()[len(
                self.ui.HostsTableView.selectionModel().selectedRows())-1].row()
            # because when we right click on a different host, we need to select it
            self.ip_clicked = self.HostsTableModel.getHostIPForRow(row)
            # select host when right-clicked
            self.ui.HostsTableView.selectRow(row)
            self.hostTableClick()

            menu, actions = self.controller.getContextMenuForHost(
                str(self.HostsTableModel.getHostCheckStatusForRow(row)))
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)
            hostid = self.HostsTableModel.getHostIdForRow(row)
            action = menu.exec_(
                self.ui.HostsTableView.viewport().mapToGlobal(pos))

            if action:
                self.controller.handleHostAction(
                    self.ip_clicked, hostid, actions, action)

    ###

    def connectServiceNamesTableContextMenu(self):
        self.ui.ServiceNamesTableView.customContextMenuRequested.connect(
            self.contextMenuServiceNamesTableView)

    def contextMenuServiceNamesTableView(self, pos):
        if len(self.ui.ServiceNamesTableView.selectionModel().selectedRows()) > 0:
            row = self.ui.ServiceNamesTableView.selectionModel().selectedRows()[len(
                self.ui.ServiceNamesTableView.selectionModel().selectedRows())-1].row()
            self.service_clicked = self.ServiceNamesTableModel.getServiceNameForRow(
                row)
            # select service when right-clicked
            self.ui.ServiceNamesTableView.selectRow(row)
            self.serviceNamesTableClick()

            menu, actions, shiftPressed = self.controller.getContextMenuForServiceName(
                self.service_clicked)
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)
            action = menu.exec_(
                self.ui.ServiceNamesTableView.viewport().mapToGlobal(pos))

            if action:
                # because we will need to populate the right-side panel in order to select those rows
                self.serviceNamesTableClick()
                # we must only fetch the targets on which we haven't run the tool yet
                tool = None
                for i in range(0, len(actions)):                         # fetch the tool name
                    if action == actions[i][1]:
                        srvc_num = actions[i][0]
                        tool = self.controller.getSettings(
                        ).portActions[srvc_num][1]
                        break

                if action.text() == 'Take screenshot':
                    tool = 'screenshooter'

                # get (IP,port,protocol) combinations for this service
                targets = []
                for row in range(self.PortsByServiceTableModel.rowCount("")):
                    targets.append([self.PortsByServiceTableModel.getIpForRow(row), self.PortsByServiceTableModel.getPortForRow(
                        row), self.PortsByServiceTableModel.getProtocolForRow(row)])

                # if the user pressed SHIFT+Right-click, ignore the rule of only running the tool on targets on which we haven't ran it yet
                if shiftPressed:
                    tool = None

                if tool:
                    # fetch the hosts that we already ran the tool on
                    hosts = self.controller.getHostsForTool(tool, 'FetchAll')
                    oldTargets = []
                    for i in range(0, len(hosts)):
                        oldTargets.append(
                            [hosts[i][5], hosts[i][6], hosts[i][7]])

                    # remove from the targets the hosts:ports we have already run the tool on
                    for host in oldTargets:
                        if host in targets:
                            targets.remove(host)

                self.controller.handleServiceNameAction(
                    targets, actions, action)

    ###

    def connectToolHostsTableContextMenu(self):
        self.ui.ToolHostsTableView.customContextMenuRequested.connect(
            self.contextToolHostsTableContextMenu)

    def contextToolHostsTableContextMenu(self, pos):
        if len(self.ui.ToolHostsTableView.selectionModel().selectedRows()) > 0:

            row = self.ui.ToolHostsTableView.selectionModel().selectedRows()[len(
                self.ui.ToolHostsTableView.selectionModel().selectedRows())-1].row()
            ip = self.ToolHostsTableModel.getIpForRow(row)
            port = self.ToolHostsTableModel.getPortForRow(row)

            if port:
                serviceName = self.controller.getServiceNameForHostAndPort(ip, port)[
                    0]

                menu, actions, terminalActions = self.controller.getContextMenuForPort(
                    str(serviceName))
                menu.aboutToShow.connect(self.setVisible)
                menu.aboutToHide.connect(self.setInvisible)

                # this can handle multiple host selection if we apply it in the future
                # get (IP,port,protocol,serviceName) combinations for each selected row                                 # context menu when the left services tab is selected
                targets = []
                for row in self.ui.ToolHostsTableView.selectionModel().selectedRows():
                    targets.append([self.ToolHostsTableModel.getIpForRow(row.row()), self.ToolHostsTableModel.getPortForRow(row.row()), self.ToolHostsTableModel.getProtocolForRow(
                        row.row()), self.controller.getServiceNameForHostAndPort(self.ToolHostsTableModel.getIpForRow(row.row()), self.ToolHostsTableModel.getPortForRow(row.row()))[0]])
                    restore = True

                action = menu.exec_(
                    self.ui.ToolHostsTableView.viewport().mapToGlobal(pos))

                if action:
                    self.controller.handlePortAction(
                        targets, actions, terminalActions, action, restore)

            # in case there was no port, we show the host menu (without the portscan / mark as checked)
            else:
                menu, actions = self.controller.getContextMenuForHost(str(
                    self.HostsTableModel.getHostCheckStatusForRow(self.HostsTableModel.getRowForIp(ip))), False)
                menu.aboutToShow.connect(self.setVisible)
                menu.aboutToHide.connect(self.setInvisible)
                hostid = self.HostsTableModel.getHostIdForRow(
                    self.HostsTableModel.getRowForIp(ip))

                action = menu.exec_(
                    self.ui.ToolHostsTableView.viewport().mapToGlobal(pos))

                if action:
                    self.controller.handleHostAction(
                        self.ip_clicked, hostid, actions, action)

    ###

    def connectServicesTableContextMenu(self):
        self.ui.ServicesTableView.customContextMenuRequested.connect(
            self.contextMenuServicesTableView)

    # this function is longer because there are two cases we are in the services table
    def contextMenuServicesTableView(self, pos):
        if len(self.ui.ServicesTableView.selectionModel().selectedRows()) > 0:

            # if there is only one row selected, get service name
            if len(self.ui.ServicesTableView.selectionModel().selectedRows()) == 1:
                row = self.ui.ServicesTableView.selectionModel().selectedRows()[len(
                    self.ui.ServicesTableView.selectionModel().selectedRows())-1].row()

                # if we are in the services tab of the hosts view
                if self.ui.ServicesTableView.isColumnHidden(0):
                    serviceName = self.ServicesTableModel.getServiceNameForRow(
                        row)
                else:                                                   # if we are in the services tab of the services view
                    serviceName = self.PortsByServiceTableModel.getServiceNameForRow(
                        row)

            else:
                # otherwise show full menu
                serviceName = '*'

            menu, actions, terminalActions = self.controller.getContextMenuForPort(
                serviceName)
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)

            # get (IP,port,protocol,serviceName) combinations for each selected row
            targets = []
            if self.ui.ServicesTableView.isColumnHidden(0):
                for row in self.ui.ServicesTableView.selectionModel().selectedRows():
                    targets.append([self.ServicesTableModel.getIpForRow(row.row()), self.ServicesTableModel.getPortForRow(row.row(
                    )), self.ServicesTableModel.getProtocolForRow(row.row()), self.ServicesTableModel.getServiceNameForRow(row.row())])
                    restore = False

            else:                                                       # context menu when the left services tab is selected
                for row in self.ui.ServicesTableView.selectionModel().selectedRows():
                    targets.append([self.PortsByServiceTableModel.getIpForRow(row.row()), self.PortsByServiceTableModel.getPortForRow(row.row(
                    )), self.PortsByServiceTableModel.getProtocolForRow(row.row()), self.PortsByServiceTableModel.getServiceNameForRow(row.row())])
                    restore = True

            action = menu.exec_(
                self.ui.ServicesTableView.viewport().mapToGlobal(pos))

            if action:
                self.controller.handlePortAction(
                    targets, actions, terminalActions, action, restore)

    ###

    def connectProcessesTableContextMenu(self):
        self.ui.ProcessesTableView.customContextMenuRequested.connect(
            self.contextMenuProcessesTableView)

    def contextMenuProcessesTableView(self, pos):
        if self.ui.ProcessesTableView.selectionModel() and self.ui.ProcessesTableView.selectionModel().selectedRows():

            menu = self.controller.getContextMenuForProcess()
            menu.aboutToShow.connect(self.setVisible)
            menu.aboutToHide.connect(self.setInvisible)

            # list of tuples (pid, status, procId)
            selectedProcesses = []
            for row in self.ui.ProcessesTableView.selectionModel().selectedRows():
                pid = self.ProcessesTableModel.getProcessPidForRow(row.row())
                selectedProcesses.append([int(pid), self.ProcessesTableModel.getProcessStatusForRow(
                    row.row()), self.ProcessesTableModel.getProcessIdForRow(row.row())])

            action = menu.exec_(
                self.ui.ProcessesTableView.viewport().mapToGlobal(pos))

            if action:
                self.controller.handleProcessAction(selectedProcesses, action)

    ###

    def connectScreenshotContextMenu(self):
        self.ui.ScreenshotWidget.scrollArea.customContextMenuRequested.connect(
            self.contextMenuScreenshot)

    def contextMenuScreenshot(self, pos):
        menu = QMenu()

        zoomInAction = menu.addAction("Zoom in (25%)")
        zoomOutAction = menu.addAction("Zoom out (25%)")
        fitToWindowAction = menu.addAction("Fit to window")
        normalSizeAction = menu.addAction("Original size")

        menu.aboutToShow.connect(self.setVisible)
        menu.aboutToHide.connect(self.setInvisible)

        action = menu.exec_(
            self.ui.ScreenshotWidget.scrollArea.viewport().mapToGlobal(pos))

        if action == zoomInAction:
            self.ui.ScreenshotWidget.zoomIn()
        elif action == zoomOutAction:
            self.ui.ScreenshotWidget.zoomOut()
        elif action == fitToWindowAction:
            self.ui.ScreenshotWidget.fitToWindow()
        elif action == normalSizeAction:
            self.ui.ScreenshotWidget.normalSize()

    #################### LEFT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def updateHostsTableView(self):
        headers = ["Id", "OS", "Accuracy", "Host", "IPv4", "IPv6", "Mac", "Status", "Hostname",
                   "Vendor", "Uptime", "Lastboot", "Distance", "CheckedHost", "State", "Count"]
        self.HostsTableModel = HostsTableModel(
            self.controller.getHostsFromDB(self.filters), headers)
        self.ui.HostsTableView.setModel(self.HostsTableModel)

        # to indicate that it doesn't need to be updated anymore
        self.lazy_update_hosts = False

        for i in [0, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]:                   # hide some columns
            self.ui.HostsTableView.setColumnHidden(i, True)

        # self.ui.HostsTableView.horizontalHeader().setResizeMode(1,2)
        self.ui.HostsTableView.horizontalHeader().resizeSection(1, 30)
        self.HostsTableModel.sort(3, Qt.DescendingOrder)

        # ensure that there is always something selected
        ips = []
        for row in range(self.HostsTableModel.rowCount("")):
            ips.append(self.HostsTableModel.getHostIPForRow(row))

        # the ip we previously clicked may not be visible anymore (eg: due to filters)
        if self.ip_clicked in ips:
            row = self.HostsTableModel.getRowForIp(self.ip_clicked)
        else:
            # or select the first row
            row = 0

        if not row == None:
            self.ui.HostsTableView.selectRow(row)
            self.hostTableClick()

    def updateServiceNamesTableView(self):
        headers = ["Name"]
        self.ServiceNamesTableModel = ServiceNamesTableModel(
            self.controller.getServiceNamesFromDB(self.filters), headers)
        self.ui.ServiceNamesTableView.setModel(self.ServiceNamesTableModel)

        # to indicate that it doesn't need to be updated anymore
        self.lazy_update_services = False

        # ensure that there is always something selected
        services = []
        for row in range(self.ServiceNamesTableModel.rowCount("")):
            services.append(
                self.ServiceNamesTableModel.getServiceNameForRow(row))

        # the service we previously clicked may not be visible anymore (eg: due to filters)
        if self.service_clicked in services:
            row = self.ServiceNamesTableModel.getRowForServiceName(
                self.service_clicked)
        else:
            # or select the first row
            row = 0

        if not row == None:
            self.ui.ServiceNamesTableView.selectRow(row)
            self.serviceNamesTableClick()

    def updateToolsTableView(self):
        if self.ui.MainTabWidget.tabText(self.ui.MainTabWidget.currentIndex()) == 'Scan' and self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Tools':
            headers = ["Progress", "Display", "Pid", "Tool", "Tool", "Host", "Port", "Protocol",
                       "Command", "Start time", "End time", "OutputFile", "Output", "Status", "Closed"]
            self.ToolsTableModel = ProcessesTableModel(
                self, self.controller.getProcessesFromDB(self.filters), headers)
            self.ui.ToolsTableView.setModel(self.ToolsTableModel)

            # to indicate that it doesn't need to be updated anymore
            self.lazy_update_tools = False

            for i in [0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]:                # hide some columns
                self.ui.ToolsTableView.setColumnHidden(i, True)

            # ensure that there is always something selected
            tools = []
            for row in range(self.ToolsTableModel.rowCount("")):
                tools.append(self.ToolsTableModel.getToolNameForRow(row))

            # the tool we previously clicked may not be visible anymore (eg: due to filters)
            if self.tool_clicked in tools:
                row = self.ToolsTableModel.getRowForToolName(self.tool_clicked)
            else:
                row = 0                                                 # or select the first row

            if not row == None:
                self.ui.ToolsTableView.selectRow(row)
                self.toolsTableClick()

    #################### RIGHT PANEL INTERFACE UPDATE FUNCTIONS ####################

    def updateServiceTableView(self, hostIP):
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId",
                   "ServiceId", "Name", "Product", "Version", "Extrainfo", "Fingerprint"]
        self.ServicesTableModel = ServicesTableModel(
            self.controller.getPortsAndServicesForHostFromDB(hostIP, self.filters), headers)
        self.ui.ServicesTableView.setModel(self.ServicesTableModel)

        # reset all the hidden columns
        for i in range(0, len(headers)):
            self.ui.ServicesTableView.setColumnHidden(i, False)

        for i in [0, 1, 5, 6, 8, 10, 11]:                                     # hide some columns
            self.ui.ServicesTableView.setColumnHidden(i, True)

        # self.ui.ServicesTableView.horizontalHeader().setResizeMode(0)
        # sort by port by default (override default)
        self.ServicesTableModel.sort(2, Qt.DescendingOrder)

    def updatePortsByServiceTableView(self, serviceName):
        headers = ["Host", "Port", "Port", "Protocol", "State", "HostId",
                   "ServiceId", "Name", "Product", "Version", "Extrainfo", "Fingerprint"]
        self.PortsByServiceTableModel = ServicesTableModel(
            self.controller.getHostsAndPortsForServiceFromDB(serviceName, self.filters), headers)
        self.ui.ServicesTableView.setModel(self.PortsByServiceTableModel)

        # reset all the hidden columns
        for i in range(0, len(headers)):
            self.ui.ServicesTableView.setColumnHidden(i, False)

        for i in [2, 5, 6, 7, 8, 10, 11]:                                     # hide some columns
            self.ui.ServicesTableView.setColumnHidden(i, True)

        # self.ui.ServicesTableView.horizontalHeader().setResizeMode(0)
        self.ui.ServicesTableView.horizontalHeader().resizeSection(0, 165)   # resize IP
        self.ui.ServicesTableView.horizontalHeader().resizeSection(1, 65)    # resize port
        self.ui.ServicesTableView.horizontalHeader(
        ).resizeSection(3, 100)   # resize protocol
        # sort by IP by default (override default)
        self.PortsByServiceTableModel.sort(0, Qt.DescendingOrder)

    def updateInformationView(self, hostIP):

        if hostIP:
            host = self.controller.getHostInformation(hostIP)

            if host:
                states = self.controller.getPortStatesForHost(host.id)
                counterOpen = counterClosed = counterFiltered = 0

                for s in states:
                    if s[0] == 'open':
                        counterOpen += 1
                    elif s[0] == 'closed':
                        counterClosed += 1
                    else:
                        counterFiltered += 1

                if host.state == 'closed':                              # check the extra ports
                    counterClosed = 65535 - counterOpen - counterFiltered
                else:
                    counterFiltered = 65535 - counterOpen - counterClosed

                self.hostInfoWidget.updateFields(host.status, counterOpen, counterClosed, counterFiltered,
                                                 host.ipv4, host.ipv6, host.macaddr, host.os_match, host.os_accuracy)

    def updateScriptsView(self, hostIP):
        headers = ["Id", "Script", "Port", "Protocol"]
        self.ScriptsTableModel = ScriptsTableModel(
            self, self.controller.getScriptsFromDB(hostIP), headers)
        self.ui.ScriptsTableView.setModel(self.ScriptsTableModel)

        for i in [0, 3]:                                                 # hide some columns
            self.ui.ScriptsTableView.setColumnHidden(i, True)

        # ensure that there is always something selected
        scripts = []
        for row in range(self.ScriptsTableModel.rowCount("")):
            scripts.append(self.ScriptsTableModel.getScriptDBIdForRow(row))

        # the script we previously clicked may not be visible anymore (eg: due to filters)
        if self.script_clicked in scripts:
            row = self.ScriptsTableModel.getRowForDBId(self.script_clicked)

        else:
            # or select the first row
            row = 0

        if not row == None:
            self.ui.ScriptsTableView.selectRow(row)
            self.scriptTableClick()

    def updateScriptsOutputView(self, scriptId):
        self.ui.ScriptsOutputTextEdit.clear()
        lines = self.controller.getScriptOutputFromDB(scriptId)
        for l in lines:
            self.ui.ScriptsOutputTextEdit.insertPlainText(l.output.rstrip())

    # TODO: check if this hack can be improved because we are calling setDirty more than we need
    def updateNotesView(self, hostid):
        self.lastHostIdClicked = str(hostid)
        note = self.controller.getNoteFromDB(hostid)

        # save the status so we can restore it after we update the note panel
        saved_dirty = self.dirty
        # clear the text box from the previous notes
        self.ui.NotesTextEdit.clear()

        if note:
            self.ui.NotesTextEdit.insertPlainText(note.text)

        if saved_dirty == False:
            self.setDirty(False)

    def updateToolHostsTableView(self, toolname):
        headers = ["Progress", "Display", "Pid", "Name", "Action", "Target", "Port",
                   "Protocol", "Command", "Start time", "OutputFile", "Output", "Status", "Closed"]
        self.ToolHostsTableModel = ProcessesTableModel(
            self, self.controller.getHostsForTool(toolname), headers)
        self.ui.ToolHostsTableView.setModel(self.ToolHostsTableModel)

        for i in [0, 1, 2, 3, 4, 7, 8, 9, 10, 11, 12, 13]:                         # hide some columns
            self.ui.ToolHostsTableView.setColumnHidden(i, True)

        self.ui.ToolHostsTableView.horizontalHeader().resizeSection(
            5, 150)  # default width for Host column

        # ensure that there is always something selected
        ids = []
        for row in range(self.ToolHostsTableModel.rowCount("")):
            ids.append(self.ToolHostsTableModel.getProcessIdForRow(row))

        # the host we previously clicked may not be visible anymore (eg: due to filters)
        if self.tool_host_clicked in ids:
            row = self.ToolHostsTableModel.getRowForDBId(
                self.tool_host_clicked)

        else:
            # or select the first row
            row = 0

        if not row == None and self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Tools':
            self.ui.ToolHostsTableView.selectRow(row)
            self.toolHostsClick()

    def updateRightPanel(self, hostIP):
        self.updateServiceTableView(hostIP)
        self.updateScriptsView(hostIP)
        # populate host info tab
        self.updateInformationView(hostIP)
        self.controller.saveProject(
            self.lastHostIdClicked, self.ui.NotesTextEdit.toPlainText())

        if hostIP:
            self.updateNotesView(self.HostsTableModel.getHostIdForRow(
                self.HostsTableModel.getRowForIp(hostIP)))
        else:
            self.updateNotesView('')

    def displayToolPanel(self, display=False):
        size = self.ui.splitter.parentWidget().width() - 210 - \
            24       # note: 24 is a fixed value
        if display:
            self.ui.ServicesTabWidget.hide()
            self.ui.splitter_3.show()
            # reset hoststableview width
            self.ui.splitter.setSizes([210, 0, size])

            if self.tool_clicked == 'screenshooter':
                self.displayScreenshots(True)
            else:
                self.displayScreenshots(False)
                # self.ui.splitter_3.setSizes([275,size-275,0])          # reset middle panel width

        else:
            self.ui.splitter_3.hide()
            self.ui.ServicesTabWidget.show()
            self.ui.splitter.setSizes([210, size, 0])

    def displayScreenshots(self, display=False):
        size = self.ui.splitter.parentWidget().width() - 210 - \
            24       # note: 24 is a fixed value

        if display:
            self.ui.DisplayWidget.hide()
            self.ui.ScreenshotWidget.scrollArea.show()
            # reset middle panel width
            self.ui.splitter_3.setSizes([275, 0, size-275])

        else:
            self.ui.ScreenshotWidget.scrollArea.hide()
            self.ui.DisplayWidget.show()
            # reset middle panel width
            self.ui.splitter_3.setSizes([275, size-275, 0])

    def displayAddHostsOverlay(self, display=False):
        if display:
            self.ui.addHostsOverlay.show()
            self.ui.HostsTableView.hide()
        else:
            self.ui.addHostsOverlay.hide()
            self.ui.HostsTableView.show()

    #################### BOTTOM PANEL INTERFACE UPDATE FUNCTIONS ####################

    def updateProcessesTableView(self):
        headers = ["Progress", "Display", "Pid", "Name", "Tool", "Host", "Port", "Protocol",
                   "Command", "Start time", "End time", "OutputFile", "Output", "Status", "Closed"]
        self.ProcessesTableModel = ProcessesTableModel(
            self, self.controller.getProcessesFromDB(self.filters, True), headers)
        self.ui.ProcessesTableView.setModel(self.ProcessesTableModel)

        for i in [1, 2, 3, 6, 7, 8, 11, 12, 14]:                                # hide some columns
            self.ui.ProcessesTableView.setColumnHidden(i, True)

        self.ui.ProcessesTableView.horizontalHeader().resizeSection(0, 125)
        self.ui.ProcessesTableView.horizontalHeader().resizeSection(4, 210)
        self.ui.ProcessesTableView.horizontalHeader().resizeSection(5, 135)
        self.ui.ProcessesTableView.horizontalHeader().resizeSection(9, 165)
        self.ui.ProcessesTableView.horizontalHeader().resizeSection(10, 165)
        self.updateProcessesIcon()

    def updateProcessesIcon(self):
        if self.ProcessesTableModel:
            for row in range(len(self.ProcessesTableModel.getProcesses())):
                status = self.ProcessesTableModel.getProcesses()[row].status

                if status == 'Waiting':
                    self.runningWidget = ImagePlayer("./images/waiting.gif")
                elif status == 'Running':
                    self.runningWidget = ImagePlayer("./images/running.gif")
                elif status == 'Finished':
                    self.runningWidget = ImagePlayer("./images/finished.gif")
                elif status == 'Crashed':  # TODO: replace gif?
                    self.runningWidget = ImagePlayer("./images/killed.gif")
                else:
                    self.runningWidget = ImagePlayer("./images/killed.gif")

                self.ui.ProcessesTableView.setIndexWidget(
                    self.ui.ProcessesTableView.model().index(row, 0), self.runningWidget)

    #################### GLOBAL INTERFACE UPDATE FUNCTION ####################

    # TODO: when nmap file is imported select last IP clicked (or first row if none)
    def updateInterface(self):
        self.ui_mainwindow.show()

        if self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Hosts':
            self.updateHostsTableView()
            self.lazy_update_services = True
            self.lazy_update_tools = True

        if self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Services':
            self.updateServiceNamesTableView()
            self.lazy_update_hosts = True
            self.lazy_update_tools = True

        if self.ui.HostsTabWidget.tabText(self.ui.HostsTabWidget.currentIndex()) == 'Tools':
            self.updateToolsTableView()
            self.lazy_update_hosts = True
            self.lazy_update_services = True

    #################### TOOL TABS ####################

    # this function creates a new tool tab for a given host
    # TODO: refactor/review, especially the restoring part. we should not check if toolname=nmap everywhere in the code
    # ..maybe we should do it here. rethink
    def createNewTabForHost(self, ip, tabtitle, restoring=False, content='', filename=''):

        # TODO: use regex otherwise tools with 'screenshot' in the name are screwed.
        if 'screenshot' in str(tabtitle):
            tempWidget = ImageViewer()
            tempWidget.setObjectName(str(tabtitle))
            tempWidget.open(str(filename))
            tempTextView = tempWidget.scrollArea
            tempTextView.setObjectName(str(tabtitle))
        else:
            tempWidget = QWidget()
            tempWidget.setObjectName(str(tabtitle))
            tempTextView = QPlainTextEdit(tempWidget)
            tempTextView.setReadOnly(True)
            if self.controller.getSettings().general_tool_output_black_background == 'True':
                p = tempTextView.palette()
                # black background
                p.setColor(QPalette.Base, Qt.black)
                p.setColor(QPalette.Text, Qt.white)               # white font
                tempTextView.setPalette(p)
                # font-size:18px; width: 150px; color:red; left: 20px;}"); # set the menu font color: black
                tempTextView.setStyleSheet("QMenu { color:black;}")
            tempLayout = QHBoxLayout(tempWidget)
            tempLayout.addWidget(tempTextView)

            if not content == '':                                       # if there is any content to display
                tempTextView.appendPlainText(content)

        # if restoring tabs (after opening a project) don't show the tab in the ui
        if restoring == False:
            # tabindex = self.ui.ServicesTabWidget.addTab(tempWidget, str(tabtitle))
            self.ui.ServicesTabWidget.addTab(tempWidget, str(tabtitle))

        # fetch tab list for this host (if any)
        hosttabs = []
        if str(ip) in self.hostTabs:
            hosttabs = self.hostTabs[str(ip)]

        if 'screenshot' in str(tabtitle):
            # add the new tab to the list
            hosttabs.append(tempWidget.scrollArea)
        else:
            # add the new tab to the list
            hosttabs.append(tempWidget)

        self.hostTabs.update({str(ip): hosttabs})

        return tempTextView

    def closeHostToolTab(self, index):
        # remember the currently selected tab
        currentTabIndex = self.ui.ServicesTabWidget.currentIndex()
        # select the tab for which the cross button was clicked
        self.ui.ServicesTabWidget.setCurrentIndex(index)

        currentWidget = self.ui.ServicesTabWidget.currentWidget()
        if 'screenshot' in str(self.ui.ServicesTabWidget.currentWidget().objectName()):
            dbId = int(currentWidget.property('dbId'))
        else:
            dbId = int(currentWidget.findChild(
                QPlainTextEdit).property('dbId'))

        pid = int(self.controller.getPidForProcess(dbId)
                  )               # the process ID (=os)

        if str(self.controller.getProcessStatusForDBId(dbId)) == 'Running':
            message = "This process is still running. Are you sure you want to kill it?"
            reply = QMessageBox.question(
                self.ui.centralwidget, 'Confirm', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.controller.killProcess(pid, dbId)
            else:
                return

        # TODO: duplicate code
        if str(self.controller.getProcessStatusForDBId(dbId)) == 'Waiting':
            message = "This process is waiting to start. Are you sure you want to cancel it?"
            reply = QMessageBox.question(
                self.ui.centralwidget, 'Confirm', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.controller.cancelProcess(dbId)
            else:
                return

        # remove tab from host tabs list
        hosttabs = []
        for ip in self.hostTabs.keys():
            if self.ui.ServicesTabWidget.currentWidget() in self.hostTabs[ip]:
                hosttabs = self.hostTabs[ip]
                hosttabs.remove(self.ui.ServicesTabWidget.currentWidget())
                self.hostTabs.update({ip: hosttabs})
                break

        # update the closed status in the db - getting the dbid
        self.controller.storeCloseTabStatusInDB(dbId)
        self.ui.ServicesTabWidget.removeTab(
            index)                      # remove the tab

        if currentTabIndex >= self.ui.ServicesTabWidget.currentIndex():     # select the initially selected tab
            # all the tab indexes shift if we remove a tab index smaller than the current tab index
            self.ui.ServicesTabWidget.setCurrentIndex(currentTabIndex - 1)
        else:
            self.ui.ServicesTabWidget.setCurrentIndex(currentTabIndex)

    # this function removes tabs that were created when running tools (starting from the end to avoid index problems)
    def removeToolTabs(self, position=-1):
        if position == -1:
            position = self.fixedTabsCount-1
        for i in range(self.ui.ServicesTabWidget.count()-1, position, -1):
            self.ui.ServicesTabWidget.removeTab(i)

    # this function restores the tool tabs based on the DB content (should be called when opening an existing project).
    def restoreToolTabs(self):
        # false means we are fetching processes with display flag=False, which is the case for every process once a project is closed.
        tools = self.controller.getProcessesFromDB(self.filters, False)
        # show a progress bar because this could take long
        nbr = len(tools)
        if nbr == 0:
            nbr = 1
        progress = 100.0 / nbr
        totalprogress = 0
        self.tick.emit(int(totalprogress))

        for t in tools:
            if not t.tabtitle == '':
                if 'screenshot' in str(t.tabtitle):
                    imageviewer = self.createNewTabForHost(t.hostip, t.tabtitle, True, '', str(
                        self.controller.getOutputFolder())+'/screenshots/'+str(t.outputfile))
                    imageviewer.setObjectName(str(t.tabtitle))
                    imageviewer.setProperty('dbId', QVariant(str(t.id)))
                else:
                    # True means we are restoring tabs. Set the widget's object name to the DB id of the process
                    self.createNewTabForHost(t.hostip, t.tabtitle, True, t.output).setProperty(
                        'dbId', QVariant(str(t.id)))

            # update the progress bar
            totalprogress += progress
            self.tick.emit(int(totalprogress))

    def restoreToolTabsForHost(self, ip):
        if (self.hostTabs) and (ip in self.hostTabs):
            # use the ip as a key to retrieve its list of tooltabs
            tabs = self.hostTabs[ip]
            for tab in tabs:
                # do not display hydra and nmap tabs when restoring for that host
                if not 'hydra' in tab.objectName() and not 'nmap' in tab.objectName():
                    # tabindex = self.ui.ServicesTabWidget.addTab(tab, tab.objectName())
                    self.ui.ServicesTabWidget.addTab(tab, tab.objectName())

    # this function restores the textview widget (now in the tools display widget) to its original tool tab (under the correct host)
    def restoreToolTabWidget(self, clear=False):
        if self.ui.DisplayWidget.findChild(QPlainTextEdit) == self.ui.toolOutputTextView:
            return

        for host in self.hostTabs.keys():
            hosttabs = self.hostTabs[host]
            for tab in hosttabs:
                if not 'screenshot' in str(tab.objectName()) and not tab.findChild(QPlainTextEdit):
                    tab.layout().addWidget(self.ui.DisplayWidget.findChild(QPlainTextEdit))
                    break

        if clear:
            # remove the tool output currently in the tools display panel
            if self.ui.DisplayWidget.findChild(QPlainTextEdit):
                self.ui.DisplayWidget.findChild(QPlainTextEdit).setParent(None)

            self.ui.DisplayWidgetLayout.addWidget(self.ui.toolOutputTextView)

    #################### BRUTE TABS ####################

    def createNewBruteTab(self, ip, port, service):
        self.ui.statusbar.showMessage(
            'Sending to Brute: '+ip+':'+port+' ('+service+')', msecs=1000)
        bWidget = BruteWidget(ip, port, service, self.controller.getSettings())
        bWidget.runButton.clicked.connect(lambda: self.callHydra(bWidget))
        self.ui.BruteTabWidget.addTab(bWidget, str(self.bruteTabCount))
        # update tab count
        self.bruteTabCount += 1
        # show the last added tab in the brute widget
        self.ui.BruteTabWidget.setCurrentIndex(
            self.ui.BruteTabWidget.count()-1)

    def closeBruteTab(self, index):
        # remember the currently selected tab
        currentTabIndex = self.ui.BruteTabWidget.currentIndex()
        # select the tab for which the cross button was clicked
        self.ui.BruteTabWidget.setCurrentIndex(index)

        if not self.ui.BruteTabWidget.currentWidget().pid == -1:        # if process is running
            if self.ProcessesTableModel.getProcessStatusForPid(self.ui.BruteTabWidget.currentWidget().pid) == "Running":
                message = "This process is still running. Are you sure you want to kill it?"
                reply = QMessageBox.question(
                    self.ui.centralwidget, 'Confirm', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
                if reply == QMessageBox.Yes:
                    self.killBruteProcess(
                        self.ui.BruteTabWidget.currentWidget())
                else:
                    return

        dbIdString = self.ui.BruteTabWidget.currentWidget().display.property('dbId')
        if dbIdString and not dbIdString == '':
            self.controller.storeCloseTabStatusInDB(int(dbIdString))

        self.ui.BruteTabWidget.removeTab(
            index)                         # remove the tab

        if currentTabIndex >= self.ui.BruteTabWidget.currentIndex():    # select the initially selected tab
            # all the tab indexes shift if we remove a tab index smaller than the current tab index
            self.ui.BruteTabWidget.setCurrentIndex(currentTabIndex - 1)
        else:
            self.ui.BruteTabWidget.setCurrentIndex(currentTabIndex)

        # if the last tab was removed, add default tab
        if self.ui.BruteTabWidget.count() == 0:
            self.createNewBruteTab('127.0.0.1', '22', 'ssh')

    def resetBruteTabs(self):
        count = self.ui.BruteTabWidget.count()
        for i in range(0, count):
            self.ui.BruteTabWidget.removeTab(count - i - 1)
        self.createNewBruteTab('127.0.0.1', '22', 'ssh')

    # TODO: show udp in tabtitle when udp service
    def callHydra(self, bWidget):
        if validateNmapInput(bWidget.ipTextinput.text()) and validateNmapInput(bWidget.portTextinput.text()) and validateCredentials(bWidget.usersTextinput.text()) and validateCredentials(bWidget.passwordsTextinput.text()):
            # check if host is already in scope
            if not self.controller.isHostInDB(bWidget.ipTextinput.text()):
                message = "This host is not in scope. Add it to scope and continue?"
                reply = QMessageBox.question(
                    self.ui.centralwidget, 'Confirm', message, QMessageBox.Yes | QMessageBox.No, QMessageBox.Yes)
                if reply == QMessageBox.No:
                    return
                else:
                    print('Adding host to scope here!!')
                    self.controller.addHosts(
                        str(bWidget.ipTextinput.text()), False, False)

            bWidget.validationLabel.hide()
            bWidget.toggleRunButton()
            bWidget.resetDisplay()                                      # fixes tab bug

            hydraCommand = bWidget.buildHydraCommand(self.controller.getRunningFolder(
            ), self.controller.getUserlistPath(), self.controller.getPasslistPath())
            bWidget.setObjectName(str("hydra"+" ("+bWidget.getPort()+"/tcp)"))

            # add widget to host tabs (needed to be able to move the widget between brute/tools tabs)
            hosttabs = []
            if str(bWidget.ip) in self.hostTabs:
                hosttabs = self.hostTabs[str(bWidget.ip)]

            hosttabs.append(bWidget)
            self.hostTabs.update({str(bWidget.ip): hosttabs})

            bWidget.pid = self.controller.runCommand("hydra", bWidget.objectName(), bWidget.ip, bWidget.getPort(
            ), 'tcp', str(hydraCommand), getTimestamp(True), bWidget.outputfile, bWidget.display)
            bWidget.runButton.clicked.disconnect()
            bWidget.runButton.clicked.connect(
                lambda: self.killBruteProcess(bWidget))

        else:
            bWidget.validationLabel.show()

    def killBruteProcess(self, bWidget):
        dbId = str(bWidget.display.property('dbId'))
        status = self.controller.getProcessStatusForDBId(dbId)
        if status == "Running":                                         # check if we need to kill or cancel
            self.controller.killProcess(
                self.controller.getPidForProcess(dbId), dbId)

        elif status == "Waiting":
            self.controller.cancelProcess(dbId)
        self.bruteProcessFinished(bWidget)

    def bruteProcessFinished(self, bWidget):
        bWidget.toggleRunButton()
        bWidget.pid = -1

        # disassociate textview from bWidget (create new textview for bWidget) and replace it with a new host tab
        self.createNewTabForHost(str(bWidget.ip), str(bWidget.objectName()), restoring=True, content=str(
            bWidget.display.toPlainText())).setProperty('dbId', QVariant(str(bWidget.display.property('dbId'))))

        # go through host tabs and find the correct bWidget
        hosttabs = []
        if str(bWidget.ip) in self.hostTabs:
            hosttabs = self.hostTabs[str(bWidget.ip)]

        if hosttabs.count(bWidget) > 1:
            hosttabs.remove(bWidget)

        self.hostTabs.update({str(bWidget.ip): hosttabs})

        bWidget.runButton.clicked.disconnect()
        bWidget.runButton.clicked.connect(lambda: self.callHydra(bWidget))

    def findFinishedBruteTab(self, pid):
        for i in range(0, self.ui.BruteTabWidget.count()):
            if str(self.ui.BruteTabWidget.widget(i).pid) == pid:
                self.bruteProcessFinished(self.ui.BruteTabWidget.widget(i))
                return

    def blinkBruteTab(self, bWidget):
        self.ui.MainTabWidget.tabBar().setTabTextColor(1, QColor('red'))
        for i in range(0, self.ui.BruteTabWidget.count()):
            if self.ui.BruteTabWidget.widget(i) == bWidget:
                self.ui.BruteTabWidget.tabBar().setTabTextColor(i, QColor('red'))
                return
