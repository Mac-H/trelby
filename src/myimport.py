import config
import gutil
import screenplay
import util

import re

from lxml import etree

import wx

from xml.etree.ElementTree import ElementTree

# special linetype that means that indent contains action and scene lines,
# and scene lines are the ones that begin with "EXT." or "INT."
SCENE_ACTION = -2

# like importTextFile, but for Final Draft files.
def importFDX(fileName, frame):
    elemMap = {
        "Action" : screenplay.ACTION,
        "Character" : screenplay.CHARACTER,
        "Dialogue" : screenplay.DIALOGUE,
        "Parenthetical" : screenplay.PAREN,
        "Scene Heading" : screenplay.SCENE,
        "Shot" : screenplay.SHOT,
        "Transition" : screenplay.TRANSITION,
    }

    # the 5 MB limit is arbitrary, we just want to avoid getting a
    # MemoryError exception for /dev/zero etc.
    data = util.loadFile(fileName, frame, 5000000)

    if data == None:
        return None

    if len(data) == 0:
        wx.MessageBox("File is empty.", "Error", wx.OK, frame)

        return None

    try:
        root = etree.XML(data)
        lines = []

        for para in root.xpath("Content//Paragraph"):
            et = para.get("Type")

            # "General" has embedded Dual Dialogue paragraphs inside it;
            # nothing to do for the General element itself.
            if et == "General":
                continue

            # all unknown linetypes are converted to Action
            lt = elemMap.get(et, screenplay.ACTION)

            s = u""
            for text in para.xpath("Text"):
                # text.text is None for paragraphs with no text, and +=
                # blows up trying to add a string object and None, so
                # guard against that
                if text.text:
                    s += text.text

            # FD uses some fancy unicode apostrophe, replace it with a
            # normal one
            s = s.replace(u"\u2019", "'")

            s = util.toLatin1(s)

            s = s.replace("\n","")
            lines.append(screenplay.Line(screenplay.LB_LAST, lt, s))

        if len(lines) == 0:
            wx.MessageBox("The file contains no importable lines", "Error", wx.OK, frame)
            return None

        return lines

    except etree.XMLSyntaxError, e:
        wx.MessageBox("Error parsing file: %s" %e, "Error", wx.OK, frame)
        return None


# import text file from fileName, return list of Line objects for the
# screenplay or None if something went wrong. returned list always
# contains at least one line.
def importTextFile(fileName, frame):

    # the 1 MB limit is arbitrary, we just want to avoid getting a
    # MemoryError exception for /dev/zero etc.
    data = util.loadFile(fileName, frame, 1000000)

    if data == None:
        return None

    if len(data) == 0:
        wx.MessageBox("File is empty.", "Error", wx.OK, frame)

        return None

    data = util.fixNL(data)
    lines = data.split("\n")

    tabWidth = 4

    # key = indent level, value = Indent
    indDict = {}

    for i in range(len(lines)):
        s = util.toInputStr(lines[i].rstrip().expandtabs(tabWidth))

        # don't count empty lines towards indentation statistics
        if s.strip() == "":
            lines[i] = ""

            continue

        cnt = util.countInitial(s, " ")

        ind = indDict.get(cnt)
        if not ind:
            ind = Indent(cnt)
            indDict[cnt] = ind

        tmp = s.upper()

        if util.multiFind(tmp, ["EXT.", "INT."]):
            ind.sceneStart += 1

        if util.multiFind(tmp, ["CUT TO:", "DISSOLVE TO:"]):
            ind.trans += 1

        if re.match(r"^ +\(.*\)$", tmp):
            ind.paren += 1

        ind.lines.append(s.lstrip())
        lines[i] = s

    if len(indDict) == 0:
        wx.MessageBox("File contains only empty lines.", "Error", wx.OK, frame)

        return None

    # scene/action indent
    setType(SCENE_ACTION, indDict, lambda v: v.sceneStart)

    # indent with most lines is dialogue in non-pure-action scripts
    setType(screenplay.DIALOGUE, indDict, lambda v: len(v.lines))

    # remaining indent with lines is character most likely
    setType(screenplay.CHARACTER, indDict, lambda v: len(v.lines))

    # transitions
    setType(screenplay.TRANSITION, indDict, lambda v: v.trans)

    # parentheticals
    setType(screenplay.PAREN, indDict, lambda v: v.paren)

    # some text files have this type of parens:
    #
    #        JOE
    #      (smiling and
    #       hopping along)
    #
    # this handles them.
    parenIndent = findIndent(indDict, lambda v: v.lt == screenplay.PAREN)
    if parenIndent != -1:
        paren2Indent = findIndent(indDict,
            lambda v, var: (v.lt == -1) and (v.indent == var),
            parenIndent + 1)

        if paren2Indent != -1:
            indDict[paren2Indent].lt = screenplay.PAREN

    # set line type to ACTION for any indents not recognized
    for v in indDict.itervalues():
        if v.lt == -1:
            v.lt = screenplay.ACTION

    dlg = ImportDlg(frame, indDict.values())

    if dlg.ShowModal() != wx.ID_OK:
        dlg.Destroy()

        return None

    dlg.Destroy()

    ret = []

    for i in range(len(lines)):
        s = lines[i]
        cnt = util.countInitial(s, " ")
        s = s.lstrip()
        sUp = s.upper()

        if s:
            lt = indDict[cnt].lt

            if lt == SCENE_ACTION:
                if s.startswith("EXT.") or s.startswith("INT."):
                    lt = screenplay.SCENE
                else:
                    lt = screenplay.ACTION

            if ret and (ret[-1].lt != lt):
                ret[-1].lb = screenplay.LB_LAST

            if lt == screenplay.CHARACTER:
                if sUp.endswith("(CONT'D)"):
                    s = sUp[:-8].rstrip()

            elif lt == screenplay.PAREN:
                if s == "(continuing)":
                    s = ""

            if s:
                line = screenplay.Line(screenplay.LB_SPACE, lt, s)
                ret.append(line)

        elif ret:
            ret[-1].lb = screenplay.LB_LAST

    if len(ret) == 0:
        ret.append(screenplay.Line(screenplay.LB_LAST, screenplay.ACTION))

    # make sure the last line ends an element
    ret[-1].lb = screenplay.LB_LAST

    return ret

# go through indents, find the one with maximum value in something, and
# set its linetype to given lt.
def setType(lt, indDict, func):
    maxCount = 0
    found = -1

    for v in indDict.itervalues():
        # don't touch indents already set
        if v.lt != -1:
            continue

        val = func(v)

        if val > maxCount:
            maxCount = val
            found = v.indent

    if found != -1:
        indDict[found].lt = lt

# go through indents calling func(it, *vars) on each. return indent count
# for the indent func returns True, or -1 if it returns False for each.
def findIndent(indDict, func, *vars):
    for v in indDict.itervalues():
        if func(v, *vars):
            return v.indent

    return -1

# information about one indent level in imported text files.
class Indent:
    def __init__(self, indent):

        # indent level, i.e. spaces at the beginning
        self.indent = indent

        # lines with this indent, leading spaces removed
        self.lines = []

        # assigned line type, or -1 if not assigned yet.
        self.lt = -1

        # how many of the lines start with "EXT." or "INT."
        self.sceneStart = 0

        # how many of the lines have "CUT TO:" or "DISSOLVE TO:"
        self.trans = 0

        # how many of the lines have a form of "^ +\(.*)$", i.e. are most
        # likely parentheticals
        self.paren = 0


class ImportDlg(wx.Dialog):
    def __init__(self, parent, indents):
        wx.Dialog.__init__(self, parent, -1, "Adjust styles",
                           style = wx.DEFAULT_DIALOG_STYLE)

        indents.sort(lambda i1, i2: -cmp(len(i1.lines), len(i2.lines)))

        vsizer = wx.BoxSizer(wx.VERTICAL)

        tmp = wx.StaticText(self, -1, "Input:")
        vsizer.Add(tmp)

        self.inputLb = wx.ListBox(self, -1, size = (400, 200))
        for it in indents:
            self.inputLb.Append("%d lines (indented %d characters)" %
                                (len(it.lines), it.indent), it)

        vsizer.Add(self.inputLb, 0, wx.EXPAND)

        hsizer = wx.BoxSizer(wx.HORIZONTAL)

        hsizer.Add(wx.StaticText(self, -1, "Style:"), 0,
                   wx.ALIGN_CENTER_VERTICAL)
        self.styleCombo = wx.ComboBox(self, -1, style = wx.CB_READONLY)

        self.styleCombo.Append("Scene / Action", SCENE_ACTION)
        for t in config.getTIs():
            self.styleCombo.Append(t.name, t.lt)

        util.setWH(self.styleCombo, w = 150)

        hsizer.Add(self.styleCombo, 0, wx.LEFT, 10)

        vsizer.Add(hsizer, 0, wx.TOP | wx.BOTTOM, 10)

        vsizer.Add(wx.StaticText(self, -1, "Lines:"))

        self.linesEntry = wx.TextCtrl(self, -1, size = (400, 200),
            style = wx.TE_MULTILINE | wx.TE_DONTWRAP)
        vsizer.Add(self.linesEntry, 0, wx.EXPAND)

        hsizer = wx.BoxSizer(wx.HORIZONTAL)

        hsizer.Add((1, 1), 1)

        cancelBtn = gutil.createStockButton(self, "Cancel")
        hsizer.Add(cancelBtn)

        okBtn = gutil.createStockButton(self, "OK")
        hsizer.Add(okBtn, 0, wx.LEFT, 10)

        vsizer.Add(hsizer, 0, wx.EXPAND | wx.TOP, 10)

        util.finishWindow(self, vsizer)

        wx.EVT_COMBOBOX(self, self.styleCombo.GetId(), self.OnStyleCombo)
        wx.EVT_LISTBOX(self, self.inputLb.GetId(), self.OnInputLb)

        wx.EVT_BUTTON(self, cancelBtn.GetId(), self.OnCancel)
        wx.EVT_BUTTON(self, okBtn.GetId(), self.OnOK)

        self.inputLb.SetSelection(0)
        self.OnInputLb()

    def OnOK(self, event):
        self.EndModal(wx.ID_OK)

    def OnCancel(self, event):
        self.EndModal(wx.ID_CANCEL)

    def OnInputLb(self, event = None):
        self.selected = self.inputLb.GetClientData(self.inputLb.GetSelection())

        util.reverseComboSelect(self.styleCombo, self.selected.lt)
        self.linesEntry.SetValue("\n".join(self.selected.lines))

    def OnStyleCombo(self, event):
        self.selected.lt = self.styleCombo.GetClientData(
            self.styleCombo.GetSelection())
