import util
from wxPython.wx import *

class CharMapDlg(wxDialog):
    def __init__(self, parent, ctrl):
        wxDialog.__init__(self, parent, -1, "Character map",
            pos = wxDefaultPosition,
            style = wxDEFAULT_DIALOG_STYLE)

        self.ctrl = ctrl
        
        hsizer = wxBoxSizer(wxHORIZONTAL)
        self.SetSizer(hsizer)

        self.charMap = MyCharMap(self)
        hsizer.Add(self.charMap)

        self.SetClientSizeWH(630, self.charMap.GetClientSize().height)

        self.CenterOnScreen()
        
        vsizer = wxBoxSizer(wxVERTICAL)
        
        self.insertButton = wxButton(self, -1, "Insert character")
        vsizer.Add(self.insertButton)
        EVT_BUTTON(self, self.insertButton.GetId(), self.OnInsert)

        hsizer.Add(vsizer, 0, wxLEFT | wxTOP, 5)
        
        self.Layout()

    def OnInsert(self, event):
        if self.charMap.selected:
            self.ctrl.OnKeyChar(util.MyKeyEvent(ord(self.charMap.selected)))
            
class MyCharMap(wxWindow):
    def __init__(self, parent):
        wxWindow.__init__(self, parent, -1)

        self.selected = None

        # all valid characters
        self.chars = ""
        
        for i in xrange(256):
            if util.isValidInputChar(i):
                self.chars += chr(i)

        self.cols = 16
        self.rows = len(self.chars) / self.cols
        if len(self.chars) % 16:
            self.rows += 1

        # offset of grid
        self.offset = 5
        
        # size of a single character cell
        self.cellSize = 32

        if wxPlatform == "__WXMSW__":
            self.smallFont = wxFont(12, wxSWISS, wxNORMAL, wxNORMAL)
            self.normalFont = wxFont(18, wxMODERN, wxNORMAL, wxBOLD)
            self.bigFont = wxFont(38, wxMODERN, wxNORMAL, wxBOLD)
        else:
            self.smallFont = wxFont(14, wxSWISS, wxNORMAL, wxNORMAL)
            self.normalFont = wxFont(26, wxMODERN, wxNORMAL, wxBOLD)
            self.bigFont = wxFont(48, wxMODERN, wxNORMAL, wxBOLD)
        
        EVT_PAINT(self, self.OnPaint)
        EVT_LEFT_DOWN(self, self.OnLeftDown)
        EVT_MOTION(self, self.OnMotion)
        EVT_SIZE(self, self.OnSize)

        self.SetClientSizeWH(523, 460)

    def OnSize(self, event):
        size = self.GetClientSize()
        self.screenBuf = wxEmptyBitmap(size.width, size.height)

    def OnLeftDown(self, event):
        pos = event.GetPosition()

        x = (pos.x - self.offset) / self.cellSize
        y = (pos.y - self.offset) / self.cellSize

        self.selected = None
        
        if (x >= 0) and (x < self.cols) and (y >= 0) and (y <= self.rows):
            i = y * self.cols + x
            if i < len(self.chars):
                self.selected = self.chars[i]
                
        self.Refresh(False)

    def OnMotion(self, event):
        if event.LeftIsDown():
            self.OnLeftDown(event)
            
    def OnPaint(self, event):
        dc = wxBufferedPaintDC(self, self.screenBuf)

        size = self.GetClientSize()
        dc.SetBrush(wxWHITE_BRUSH)
        dc.SetPen(wxWHITE_PEN)
        dc.DrawRectangle(0, 0, size.width, size.height)

        dc.SetPen(wxBLACK_PEN)
        dc.SetTextForeground(wxBLACK)
        
        for y in range(self.rows + 1):
            util.drawLine(dc, self.offset, self.offset + y * self.cellSize,
                          self.cols * self.cellSize, 0)

        for x in range(self.cols + 1):
            util.drawLine(dc, self.offset + x * self.cellSize,
                self.offset, 0, self.rows * self.cellSize)

        dc.SetFont(self.normalFont)
        
        for y in range(self.rows):
            for x in range(self.cols):
                i = y * self.cols + x
                if i < len(self.chars):
                    util.drawText(dc, self.chars[i],
                        x * self.cellSize + self.offset + self.cellSize / 2,
                        y * self.cellSize + self.offset + self.cellSize / 2,
                        util.ALIGN_CENTER, util.VALIGN_CENTER)
            
        y = self.offset + self.rows * self.cellSize
        pad = 5
        dc.SetFont(self.smallFont)
            
        if self.selected:
            self.drawCharBox(dc, "Selected:", self.selected, self.offset,
                             y + pad, 75)
            
            c = util.upper(self.selected)
            if c == self.selected:
                c = util.lower(self.selected)
                if c == self.selected:
                    c = None

            if c:
                self.drawCharBox(dc, "Opposite case:", c, self.offset + 150,
                                 y + pad, 110)

            dc.SetFont(self.smallFont)
            dc.DrawText("Character code: %d" % ord(self.selected),
                        360, y + pad)
        else:
            dc.DrawText("Click on a character to select it.", self.offset,
                        y + pad)
                
    def drawCharBox(self, dc, text, char, x, y, xinc):
        dc.SetFont(self.smallFont)

        dc.DrawText(text, x, y)

        boxX = x + xinc
        boxSize = 60

        dc.DrawRectangle(boxX, y, boxSize, boxSize)

        dc.SetFont(self.bigFont)
        util.drawText(dc, char, boxX + boxSize / 2, y + boxSize / 2,
                      util.ALIGN_CENTER, util.VALIGN_CENTER)