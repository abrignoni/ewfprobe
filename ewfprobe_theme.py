"""Light and dark colours, and the header, for the ewfprobe window.

Standard library only. It gives the window the look of the other windows in this family of
tools (AppWalk and the probes): a light grey page, white bordered panels, one blue button for the
main action and outlined buttons for the rest, and a dark version of all of it.

ttk widgets are recoloured through ttk.Style on the 'clam' theme (native themes such as Windows'
'vista' and macOS 'aqua' ignore colours). Classic Tk widgets (Text, Listbox, Canvas, Menu,
Toplevel) get colours both directly and through the option database, so ones made later match.
On Windows 10/11 the title bars follow with DwmSetWindowAttribute.

The logo is read from the assets folder beside this file (or inside a frozen build). When it is
missing the window shows no logo and works the same.
"""

import os
import subprocess
import sys
import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

# The same colours as AppWalk's window; each mode is a full set.
LIGHT = {'bg': '#F3F4F6', 'card': '#FFFFFF', 'soft': '#EEF0F3', 'field': '#FFFFFF', 'fg': '#111827',
         'muted': '#6B7280', 'line': '#D9DEE5', 'edge': '#B8C0CC', 'accent': '#2563EB', 'accent_down': '#1D4ED8',
         'accent_off': '#AFC0EC', 'ink_off': '#9AA4B1', 'select': '#DCE7FD', 'select_fg': '#111827',
         'hover': '#E8EBF0', 'ok': '#15803D', 'warn': '#B45309', 'bad': '#B91C1C'}
DARK = {'bg': '#111318', 'card': '#1A1D23', 'soft': '#22262E', 'field': '#1F232A', 'fg': '#E6E8EC',
        'muted': '#9AA3AF', 'line': '#2C313A', 'edge': '#4A5362', 'accent': '#3B82F6', 'accent_down': '#2563EB',
        'accent_off': '#33415F', 'ink_off': '#6B7585', 'select': '#24427A', 'select_fg': '#FFFFFF',
        'hover': '#2A2F38', 'ok': '#4ADE80', 'warn': '#F5B041', 'bad': '#FF7B72'}
# Older code in these windows reads these names.
for _c in (LIGHT, DARK):
    _c.update(panel=_c['card'], button=_c['card'], heading=_c['soft'])


def assets_dir(here):
    """The assets folder: beside the script, or unpacked inside a PyInstaller build."""
    return os.path.join(getattr(sys, '_MEIPASS', here), 'assets')


def system_dark():
    """True when the operating system is set to dark, where that can be read; otherwise False."""
    try:
        if sys.platform == 'darwin':
            done = subprocess.run(['defaults', 'read', '-g', 'AppleInterfaceStyle'], capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=5, check=False)
            return b'Dark' in done.stdout
        if os.name == 'nt':
            import winreg  # pylint: disable=import-outside-toplevel
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                                r'Software\Microsoft\Windows\CurrentVersion\Themes\Personalize') as key:
                return not winreg.QueryValueEx(key, 'AppsUseLightTheme')[0]
    except (OSError, subprocess.SubprocessError):
        pass
    return False


def window_icon(root, folder, name):
    """The tool's logo as the icon of its windows (dock, taskbar, title bar) instead of Python's.
    Returns True when it was set. A missing file leaves the default icon."""
    try:
        icons = [tk.PhotoImage(master=root, file=os.path.join(folder, f'{name}_{s}.png')) for s in (256, 64, 32)]
        root.iconphoto(True, *icons)
        root._family_icons = icons   # Tk drops an image nothing in Python holds  pylint: disable=protected-access
    except (tk.TclError, OSError):
        return False
    if sys.platform.startswith('win'):
        try:
            root.iconbitmap(default=os.path.join(folder, f'{name}.ico'))
        except tk.TclError:
            pass
    return True


def _title_bar(window, dark):
    if sys.platform != 'win32':
        return
    try:
        import ctypes  # pylint: disable=import-outside-toplevel
        window.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
        value = ctypes.c_int(1 if dark else 0)
        for attribute in (20, 19):   # DWMWA_USE_IMMERSIVE_DARK_MODE (newer, then older Windows 10)
            if ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(value),
                                                          ctypes.sizeof(value)) == 0:
                break
    except (AttributeError, OSError, tk.TclError):
        pass


def _walk(widget):
    yield widget
    for child in widget.winfo_children():
        yield from _walk(child)


def _reset_popdown(combobox):
    """Forget a combobox's drop-down list, so the next opening builds it in the current colours.

    Tk builds that list (a Listbox Python does not see, so _walk misses it) the first time the
    combobox opens, from the option database at that moment, and keeps it. Destroyed, it is
    built again the next time the combobox opens.
    """
    popdown = f'{combobox}.popdown'
    try:
        if combobox.tk.call('winfo', 'exists', popdown):
            combobox.tk.call('destroy', popdown)
    except tk.TclError:
        pass


class Theme:  # pylint: disable=too-many-instance-attributes
    """Applies the light or dark colours to a window and everything in it.

    Styles it defines, beyond the plain ttk ones:
      Primary.TButton            the blue button: the one main action of a panel
      TButton                    the outlined button: every other action
      Header.TFrame / .TLabel    the band at the top, with Title.TLabel and HeaderMuted.TLabel
      Card.TFrame / Card.TLabel  a white panel with a thin border; CardMuted.TLabel, CardTitle.TLabel,
                                 Card.TCheckbutton, Card.TRadiobutton
      Muted.TLabel               secondary text on the page
      Ok.TLabel Warn.TLabel Bad.TLabel   status text (and Card. variants)
      Line.TFrame                a 1 px rule
    """

    def __init__(self, root):
        self.root = root
        self.style = ttk.Style(root)
        self.dark = False
        self.colours = LIGHT
        self._check_size = None
        self._check_images = {}
        self._segments = []
        base = tkfont.nametofont('TkDefaultFont')
        size = abs(base.actual('size')) or 10
        self.font_title = base.copy()
        self.font_title.configure(size=size + 5, weight='bold')
        self.font_bold = base.copy()
        self.font_bold.configure(weight='bold')
        self.font_small = base.copy()
        self.font_small.configure(size=max(8, size - 1))
        root.bind_class('Toplevel', '<Map>', lambda e: _title_bar(e.widget, self.dark), add='+')

    def __getitem__(self, key):
        return self.colours[key]

    def apply(self, dark):  # pylint: disable=too-many-statements
        self.dark = bool(dark)
        c = self.colours = DARK if self.dark else LIGHT
        style, root = self.style, self.root
        style.theme_use('clam')
        style.configure('.', background=c['bg'], foreground=c['fg'], fieldbackground=c['field'],
                        bordercolor=c['line'], darkcolor=c['bg'], lightcolor=c['bg'], troughcolor=c['soft'],
                        insertcolor=c['fg'], selectbackground=c['accent'], selectforeground='#FFFFFF',
                        arrowcolor=c['muted'], focuscolor=c['accent'])
        style.map('.', background=[('disabled', c['bg'])], foreground=[('disabled', c['ink_off'])])

        style.configure('TFrame', background=c['bg'])
        style.configure('Header.TFrame', background=c['card'])
        style.configure('Card.TFrame', background=c['card'], bordercolor=c['line'], relief='solid', borderwidth=1)
        style.configure('Line.TFrame', background=c['line'])
        style.configure('TLabel', background=c['bg'], foreground=c['fg'])
        style.configure('Muted.TLabel', background=c['bg'], foreground=c['muted'])
        style.configure('Header.TLabel', background=c['card'], foreground=c['fg'])
        style.configure('HeaderMuted.TLabel', background=c['card'], foreground=c['muted'])
        style.configure('Title.TLabel', background=c['card'], foreground=c['fg'], font=self.font_title)
        style.configure('Card.TLabel', background=c['card'], foreground=c['fg'])
        style.configure('CardMuted.TLabel', background=c['card'], foreground=c['muted'])
        style.configure('CardTitle.TLabel', background=c['card'], foreground=c['fg'], font=self.font_bold)
        for name in ('Ok', 'Warn', 'Bad'):
            style.configure(f'{name}.TLabel', background=c['bg'], foreground=c[name.lower()])
            style.configure(f'Card{name}.TLabel', background=c['card'], foreground=c[name.lower()])

        style.configure('TButton', background=c['card'], foreground=c['fg'], bordercolor=c['line'],
                        lightcolor=c['card'], darkcolor=c['card'], padding=(12, 5), width=-8, focusthickness=1,
                        focuscolor=c['accent'])
        style.map('TButton', background=[('disabled', c['bg']), ('pressed', c['soft']), ('active', c['hover'])],
                  lightcolor=[('pressed', c['soft']), ('active', c['hover'])],
                  darkcolor=[('pressed', c['soft']), ('active', c['hover'])],
                  bordercolor=[('focus', c['accent'])], foreground=[('disabled', c['ink_off'])])
        style.configure('Primary.TButton', background=c['accent'], foreground='#FFFFFF', bordercolor=c['accent'],
                        lightcolor=c['accent'], darkcolor=c['accent'], font=self.font_bold, padding=(16, 5))
        style.map('Primary.TButton',
                  background=[('disabled', c['accent_off']), ('pressed', c['accent_down']), ('active', c['accent_down'])],
                  lightcolor=[('disabled', c['accent_off']), ('active', c['accent_down'])],
                  darkcolor=[('disabled', c['accent_off']), ('active', c['accent_down'])],
                  bordercolor=[('disabled', c['accent_off']), ('focus', c['fg'])],
                  foreground=[('disabled', c['card'] if not self.dark else c['ink_off'])])
        style.configure('Segment.TButton', background=c['soft'], foreground=c['muted'], bordercolor=c['line'],
                        lightcolor=c['soft'], darkcolor=c['soft'], padding=(12, 3), width=0, font=self.font_small)
        style.map('Segment.TButton', background=[('active', c['hover'])], foreground=[('active', c['fg'])])
        style.configure('SegmentOn.TButton', background=c['accent'], foreground='#FFFFFF', bordercolor=c['accent'],
                        lightcolor=c['accent'], darkcolor=c['accent'], padding=(12, 3), width=0, font=self.font_small)
        style.map('SegmentOn.TButton', background=[('active', c['accent_down'])])

        for name in ('TEntry', 'TSpinbox'):
            style.configure(name, fieldbackground=c['field'], foreground=c['fg'], bordercolor=c['line'],
                            lightcolor=c['field'], darkcolor=c['field'], padding=4, insertcolor=c['fg'])
            style.map(name, bordercolor=[('focus', c['accent'])], lightcolor=[('focus', c['accent'])],
                      fieldbackground=[('readonly', c['soft']), ('disabled', c['soft'])])
        style.configure('TCombobox', fieldbackground=c['field'], foreground=c['fg'], background=c['card'],
                        bordercolor=c['line'], lightcolor=c['field'], darkcolor=c['field'], arrowcolor=c['muted'],
                        selectbackground=c['field'], selectforeground=c['fg'], padding=4)
        style.map('TCombobox', fieldbackground=[('readonly', c['field'])], foreground=[('readonly', c['fg'])],
                  background=[('active', c['hover']), ('readonly', c['card'])], bordercolor=[('focus', c['accent'])],
                  selectbackground=[('readonly', c['field'])], selectforeground=[('readonly', c['fg'])])
        root.option_add('*TCombobox*Listbox.background', c['field'])
        root.option_add('*TCombobox*Listbox.foreground', c['fg'])
        root.option_add('*TCombobox*Listbox.selectBackground', c['select'])
        root.option_add('*TCombobox*Listbox.selectForeground', c['select_fg'])

        self._indicators(c)
        for prefix, bg in (('', c['bg']), ('Card.', c['card'])):
            for kind in ('TCheckbutton', 'TRadiobutton'):
                style.configure(prefix + kind, background=bg, foreground=c['fg'])
                style.map(prefix + kind, background=[('active', bg)])

        style.configure('TNotebook', background=c['bg'], bordercolor=c['line'], tabmargins=(0, 4, 0, 0))
        style.configure('TNotebook.Tab', background=c['bg'], foreground=c['muted'], bordercolor=c['line'],
                        lightcolor=c['bg'], padding=(12, 4))
        style.map('TNotebook.Tab', background=[('selected', c['card'])], foreground=[('selected', c['fg'])],
                  lightcolor=[('selected', c['card'])])
        style.configure('TLabelframe', background=c['bg'], bordercolor=c['line'], lightcolor=c['bg'], darkcolor=c['bg'])
        style.configure('TLabelframe.Label', background=c['bg'], foreground=c['fg'], font=self.font_bold)

        line = max(tkfont.nametofont(f).metrics('linespace') for f in ('TkDefaultFont', 'TkTextFont'))
        style.configure('Treeview', background=c['field'], fieldbackground=c['field'], foreground=c['fg'],
                        bordercolor=c['line'], lightcolor=c['field'], darkcolor=c['field'], rowheight=line + 8)
        style.map('Treeview', background=[('selected', c['select'])], foreground=[('selected', c['select_fg'])])
        style.configure('Treeview.Heading', background=c['soft'], foreground=c['muted'], bordercolor=c['line'],
                        lightcolor=c['soft'], darkcolor=c['soft'], relief='flat', padding=(6, 4), font=self.font_small)
        style.map('Treeview.Heading', background=[('active', c['hover'])], foreground=[('active', c['fg'])])

        style.configure('TProgressbar', background=c['accent'], troughcolor=c['soft'], bordercolor=c['soft'],
                        lightcolor=c['accent'], darkcolor=c['accent'], thickness=8)
        style.configure('TScrollbar', background=c['soft'], troughcolor=c['bg'], bordercolor=c['bg'],
                        lightcolor=c['soft'], darkcolor=c['soft'], arrowcolor=c['muted'], gripcount=0)
        style.map('TScrollbar', background=[('active', c['edge'])])
        style.configure('TPanedwindow', background=c['bg'])
        style.configure('Sash', sashthickness=6, gripcount=0, background=c['bg'], lightcolor=c['bg'],
                        bordercolor=c['bg'])
        style.configure('TSeparator', background=c['line'])

        classic = {'background': c['field'], 'foreground': c['fg'], 'insertbackground': c['fg'],
                   'selectbackground': c['select'], 'selectforeground': c['select_fg'],
                   'highlightbackground': c['line'], 'highlightcolor': c['accent'], 'highlightthickness': 1,
                   'borderwidth': 0, 'relief': 'flat'}
        menu = {'background': c['card'], 'foreground': c['fg'], 'activebackground': c['accent'],
                'activeforeground': '#FFFFFF', 'disabledforeground': c['ink_off']}
        for name, value in (('*Text.background', c['field']), ('*Text.foreground', c['fg']),
                            ('*Text.insertBackground', c['fg']), ('*Text.selectBackground', c['select']),
                            ('*Text.selectForeground', c['select_fg']), ('*Text.highlightBackground', c['line']),
                            ('*Text.highlightColor', c['accent']), ('*Text.relief', 'flat'),
                            ('*Listbox.background', c['field']), ('*Listbox.foreground', c['fg']),
                            ('*Listbox.selectBackground', c['select']), ('*Listbox.selectForeground', c['select_fg']),
                            ('*Menu.background', c['card']), ('*Menu.foreground', c['fg']),
                            ('*Menu.activeBackground', c['accent']), ('*Menu.activeForeground', '#FFFFFF'),
                            ('*Toplevel.background', c['bg']), ('*Canvas.background', c['field'])):
            root.option_add(name, value)
        root.configure(background=c['bg'])
        for widget in _walk(root):
            cls = widget.winfo_class()
            if cls in ('Text', 'Listbox'):
                self._recolour(widget, classic)
            elif cls == 'Canvas':
                self._recolour(widget, {'background': c['field'], 'highlightbackground': c['line']})
            elif cls == 'Menu':
                self._recolour(widget, menu)
            elif cls == 'TCombobox':
                _reset_popdown(widget)
            elif cls in ('Toplevel', 'Tk'):
                self._recolour(widget, {'background': c['bg']})
                _title_bar(widget, self.dark)
        for light, dark in self._segments:
            light.configure(style='Segment.TButton' if self.dark else 'SegmentOn.TButton')
            dark.configure(style='SegmentOn.TButton' if self.dark else 'Segment.TButton')

    def header(self, parent, name, detail='', logo_folder=None, on_mode=None):
        """The band at the top: logo, name, a short muted detail, and a Light / Dark switch on the
        right that calls on_mode(dark). Returns (frame, right) where right is a frame for more
        controls beside the switch. Packed by the caller."""
        outer = ttk.Frame(parent)
        band = ttk.Frame(outer, style='Header.TFrame', padding=(18, 10))
        band.pack(fill='x')
        ttk.Frame(outer, style='Line.TFrame', height=1).pack(fill='x')
        self.logo = None
        if logo_folder:
            try:
                self.logo = tk.PhotoImage(master=self.root, file=os.path.join(logo_folder, f'{name}_36.png'))
            except (tk.TclError, OSError):
                self.logo = None
        if self.logo is not None:
            ttk.Label(band, image=self.logo, style='Header.TLabel').pack(side='left', padx=(0, 10))
        ttk.Label(band, text=name, style='Title.TLabel').pack(side='left')
        if detail:
            ttk.Label(band, text=detail, style='HeaderMuted.TLabel').pack(side='left', padx=(10, 0), pady=(4, 0))
        right = ttk.Frame(band, style='Header.TFrame')
        right.pack(side='right')
        if on_mode is not None:
            switch = ttk.Frame(right, style='Header.TFrame')
            switch.pack(side='right')
            light = ttk.Button(switch, text='Light', takefocus=False, command=lambda: on_mode(False))
            dark = ttk.Button(switch, text='Dark', takefocus=False, command=lambda: on_mode(True))
            light.pack(side='left')
            dark.pack(side='left')
            self._segments.append((light, dark))
            light.configure(style='Segment.TButton' if self.dark else 'SegmentOn.TButton')
            dark.configure(style='SegmentOn.TButton' if self.dark else 'Segment.TButton')
        return outer, right

    def card(self, parent, title=None, sub=None, padding=(16, 12)):
        """A bordered white panel. Returns (outer, inner): pack or grid the outer, fill the inner."""
        outer = ttk.Frame(parent, style='Card.TFrame', padding=1)
        inner = ttk.Frame(outer, style='Header.TFrame', padding=padding)
        inner.pack(fill='both', expand=True)
        if title:
            ttk.Label(inner, text=title, style='CardTitle.TLabel').pack(anchor='w')
        if sub:
            ttk.Label(inner, text=sub, style='CardMuted.TLabel').pack(anchor='w', pady=(0, 6))
        return outer, inner

    def _indicators(self, c):
        """Draw the check box (a tick, where clam draws a cross) and the radio dot at a size that
        follows the font, in the current colours, on both the page and the panel background."""
        size = max(12, tkfont.nametofont('TkDefaultFont').metrics('linespace') * 2 // 3)
        key = (size, self.dark)
        if key not in self._check_images:
            images = {}
            for bg_name in ('bg', 'card'):
                images[bg_name] = (self._box(size, c, False, c[bg_name]), self._box(size, c, True, c[bg_name]),
                                   self._dot(size, c, False, c[bg_name]), self._dot(size, c, True, c[bg_name]))
            self._check_images[key] = images
        images = self._check_images[key]
        for bg_name, prefix in (('bg', ''), ('card', 'Card.')):
            off, on, roff, ron = images[bg_name]
            tag = f'Family{"Dark" if self.dark else "Light"}{bg_name}{size}'
            for element, pair in ((f'{tag}Check.indicator', (off, on)), (f'{tag}Radio.indicator', (roff, ron))):
                try:
                    self.style.element_create(element, 'image', pair[0], ('selected', pair[1]),
                                              ('alternate', pair[0]), border=0, sticky='')
                except tk.TclError:
                    pass   # made on an earlier switch to this mode
            for kind, element in (('TCheckbutton', f'{tag}Check.indicator'),
                                  ('TRadiobutton', f'{tag}Radio.indicator')):
                part = 'Checkbutton' if kind == 'TCheckbutton' else 'Radiobutton'
                self.style.layout(prefix + kind, [(f'{part}.padding', {'sticky': 'nswe', 'children': [
                    (element, {'side': 'left', 'sticky': ''}),
                    (f'{part}.focus', {'side': 'left', 'sticky': 'w', 'children': [
                        (f'{part}.label', {'sticky': 'nswe'})]})]})])
                self.style.configure(prefix + kind, padding=(2, 2), indicatormargin=0)

    def _box(self, n, c, checked, bg):
        img = tk.PhotoImage(master=self.root, width=n + 6, height=n)   # 6px gap before the label
        fill = c['accent'] if checked else c['field']
        edge = c['accent'] if checked else c['edge']
        rows = []
        for y in range(n):
            row = []
            for x in range(n):
                corner = (x in (0, n - 1)) and (y in (0, n - 1))
                border = x in (0, n - 1) or y in (0, n - 1) or (n > 14 and (x in (1, n - 2) or y in (1, n - 2)))
                row.append(bg if corner else edge if border else fill)
            row += [bg] * 6
            rows.append('{' + ' '.join(row) + '}')
        img.put(' '.join(rows))
        if checked:   # tick from about (22%, 52%) down to (42%, 72%) then up to (78%, 28%)
            t = max(2, n // 8)
            pts = [(0.22, 0.52), (0.42, 0.72), (0.78, 0.28)]
            for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
                steps = n * 2
                for i in range(steps + 1):
                    x = (x0 + (x1 - x0) * i / steps) * n
                    y = (y0 + (y1 - y0) * i / steps) * n
                    for dx in range(t):
                        for dy in range(t):
                            px, py = int(x - t / 2 + dx), int(y - t / 2 + dy)
                            if 1 < px < n - 2 and 1 < py < n - 2:
                                img.put('#FFFFFF', (px, py))
        return img

    def _dot(self, n, c, checked, bg):
        img = tk.PhotoImage(master=self.root, width=n + 6, height=n)
        r = (n - 1) / 2
        rows = []
        for y in range(n):
            row = []
            for x in range(n):
                d = ((x - r) ** 2 + (y - r) ** 2) ** 0.5
                if d > r + 0.3:
                    row.append(bg)
                elif d > r - (2 if n > 14 else 1):
                    row.append(c['accent'] if checked else c['edge'])
                elif checked and d <= r * 0.45:
                    row.append(c['accent'])
                else:
                    row.append(c['field'])
            row += [bg] * 6
            rows.append('{' + ' '.join(row) + '}')
        img.put(' '.join(rows))
        return img

    @staticmethod
    def _recolour(widget, colours):
        for key, value in colours.items():
            try:
                widget.configure(**{key: value})
            except tk.TclError:
                pass
