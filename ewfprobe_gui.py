#!/usr/bin/env python3
"""ewfprobe GUI: a tkinter window over ewfprobe.py.

Standard library only, like the tool it drives. The window runs the command line
tool as a subprocess with the same options it takes, so what it shows is what the
command line prints:

  Info           the acquisition's geometry and metadata.
  Verify         recomputes the media hash and compares it with the stored one; the
                 progress bar follows the percentage ewfprobe prints on stderr.
  List entries   the entries of an L01 or AD1, in a table.
  Export...      writes the acquired disk out as a raw image, or, when an entry is
                 selected in the table, that entry's content.

A password, when one is given, reaches the subprocess in its environment, never on
its command line, where the process list would show it. The image is only read.

    python3 ewfprobe_gui.py                   open the window
    python3 ewfprobe_gui.py IMAGE             open it with the image chosen
    python3 ewfprobe_gui.py --cli ...         run the command line tool; this is how the
                                              window starts it, and what makes one
                                              frozen executable work
    python3 ewfprobe_gui.py --smoke IMAGE     no visible window: build it, verify the
                                              image through it, print the outcome, exit
"""

import json
import os
import queue
import re
import runpy
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import ewfprobe  # noqa: E402  pylint: disable=wrong-import-position

TITLE = "ewfprobe"
PERCENT = re.compile(r"(\d+(?:\.\d+)?)%")
PASSWORD_ENV = "EWFPROBE_GUI_PASSWORD"


def probe_command():
    """How to start the command line tool as a subprocess (see run_cli)."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--cli"]
    return [sys.executable, os.path.abspath(__file__), "--cli"]


def run_cli(argv):
    """Run ewfprobe's command line with these arguments, in this process."""
    sys.argv = ["ewfprobe.py"] + list(argv)
    try:
        runpy.run_module("ewfprobe", run_name="__main__", alter_sys=False)
    except SystemExit as done:
        return done.code if isinstance(done.code, int) else (0 if done.code is None else 1)
    return 0


def build_window(initial_image="", smoke=None):
    """Build the window. With ``smoke`` = image path it verifies once, hidden."""
    import tkinter as tk  # pylint: disable=import-outside-toplevel
    from tkinter import filedialog, messagebox, ttk  # pylint: disable=import-outside-toplevel

    root = tk.Tk()
    root.title(f"{TITLE} {ewfprobe.__version__}")
    root.geometry("940x640")
    root.minsize(720, 480)
    if smoke:
        root.attributes("-alpha", 0.0)
    state = {"proc": None, "streams": 0, "mode": None, "result": None, "out": []}
    lines = queue.Queue()

    form = ttk.Frame(root, padding=8)
    form.pack(fill="x")
    v_image = tk.StringVar(value=initial_image)
    v_password = tk.StringVar()
    v_key = tk.StringVar()
    ttk.Label(form, text="Image").grid(row=0, column=0, sticky="w", padx=(0, 6), pady=2)
    ttk.Entry(form, textvariable=v_image).grid(row=0, column=1, sticky="ew", pady=2)
    pick = ttk.Frame(form)
    pick.grid(row=0, column=2, sticky="w", padx=(6, 0))
    ttk.Button(pick, text="File...", command=lambda: v_image.set(
        filedialog.askopenfilename(title="Image") or v_image.get())).pack(side="left")
    ttk.Button(pick, text="Folder...", command=lambda: v_image.set(
        filedialog.askdirectory(title="Image folder (.sparsebundle, .afd)") or v_image.get())
               ).pack(side="left", padx=(4, 0))
    ttk.Label(form, text="Password").grid(row=1, column=0, sticky="w", padx=(0, 6), pady=2)
    ttk.Entry(form, textvariable=v_password, show="*").grid(row=1, column=1, sticky="ew", pady=2)
    ttk.Label(form, text="only for an encrypted image", foreground="gray").grid(row=1, column=2, sticky="w", padx=(6, 0))
    ttk.Label(form, text="Private key").grid(row=2, column=0, sticky="w", padx=(0, 6), pady=2)
    ttk.Entry(form, textvariable=v_key).grid(row=2, column=1, sticky="ew", pady=2)
    ttk.Button(form, text="Browse...", command=lambda: v_key.set(
        filedialog.askopenfilename(title="Private key (PEM or DER)") or v_key.get())
               ).grid(row=2, column=2, sticky="w", padx=(6, 0))
    form.columnconfigure(1, weight=1)

    buttons = ttk.Frame(root, padding=(8, 0))
    buttons.pack(fill="x")
    b_info = ttk.Button(buttons, text="Info")
    b_verify = ttk.Button(buttons, text="Verify")
    b_files = ttk.Button(buttons, text="List entries")
    b_export = ttk.Button(buttons, text="Export...")
    b_cancel = ttk.Button(buttons, text="Cancel", state="disabled")
    actions = (b_info, b_verify, b_files, b_export)
    for button in actions + (b_cancel,):
        button.pack(side="left", padx=(0, 6))
    ttk.Label(buttons, text="List entries is for L01 and AD1; select one to export it alone",
              foreground="gray").pack(side="left", padx=(6, 0))

    status_bar = ttk.Frame(root, padding=(8, 6))
    status_bar.pack(fill="x")
    progress = ttk.Progressbar(status_bar, mode="determinate", maximum=100)
    progress.pack(side="left", fill="x", expand=True)
    status = ttk.Label(status_bar, text="Choose an image.", width=44)
    status.pack(side="left", padx=(8, 0))

    panes = ttk.PanedWindow(root, orient="vertical")
    panes.pack(fill="both", expand=True, padx=8, pady=(0, 8))
    table_frame = ttk.Frame(panes)
    table = ttk.Treeview(table_frame, show="headings", columns=("kind", "size", "md5", "path"))
    for column, width in (("kind", 70), ("size", 110), ("md5", 260), ("path", 420)):
        table.heading(column, text=column)
        table.column(column, width=width, stretch=column == "path")
    scroll = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
    table.configure(yscrollcommand=scroll.set)
    table.pack(side="left", fill="both", expand=True)
    scroll.pack(side="left", fill="y")
    log = tk.Text(panes, height=12, wrap="none", state="disabled")
    panes.add(log, weight=2)
    panes.add(table_frame, weight=2)

    def write(text):
        log.configure(state="normal")
        log.insert("end", text)
        log.see("end")
        log.configure(state="disabled")

    def pump(stream, tag):
        # ewfprobe rewrites its progress line with \r, so split on both endings.
        buffer = b""
        for chunk in iter(lambda: stream.read1(4096), b""):
            buffer += chunk
            parts = re.split(rb"\r|\n", buffer)
            buffer = parts.pop()
            for part in parts:
                lines.put((tag, part.decode("utf-8", "replace")))
        if buffer:
            lines.put((tag, buffer.decode("utf-8", "replace")))
        lines.put((tag, None))

    def start(mode, output=None, entry=None):
        image = v_image.get().strip()
        if not os.path.exists(image):
            messagebox.showinfo(TITLE, "Choose an image first.")
            return
        args = probe_command() + [mode]
        env = dict(os.environ)
        if v_password.get():
            env[PASSWORD_ENV] = v_password.get()
            args += ["--password-env", PASSWORD_ENV]
        if v_key.get().strip():
            args += ["--private-key", v_key.get().strip()]
        if mode == "export":
            args += ["-o", output]
            if entry:
                args += ["--entry", entry]
        args.append(image)
        log.configure(state="normal")
        log.delete("1.0", "end")
        log.configure(state="disabled")
        if mode == "files":
            table.delete(*table.get_children())
        shown = ["ewfprobe.py"] + args[args.index("--cli") + 1:]
        write("$ " + " ".join(a if " " not in a else f'"{a}"' for a in shown) + "\n\n")
        state.update(mode=mode, out=[], header=True)
        progress["value"] = 0
        status["text"] = "running..."
        for button in actions:
            button["state"] = "disabled"
        b_cancel["state"] = "normal"
        try:
            state["proc"] = subprocess.Popen(  # pylint: disable=consider-using-with
                args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, env=env)
        except OSError as error:
            messagebox.showerror(TITLE, f"Could not start ewfprobe: {error}")
            finish(None)
            return
        state["streams"] = 2
        threading.Thread(target=pump, args=(state["proc"].stdout, "out"), daemon=True).start()
        threading.Thread(target=pump, args=(state["proc"].stderr, "err"), daemon=True).start()
        root.after(50, poll)

    def export():
        selection = table.selection()
        entry = table.item(selection[0], "values")[3] if selection else None
        if selection and table.item(selection[0], "values")[0] != "file":
            messagebox.showinfo(TITLE, "Select a file entry, or clear the selection to export the disk.")
            return
        output = filedialog.asksaveasfilename(
            title="Export entry" if entry else "Export raw image",
            initialfile=os.path.basename(entry) if entry else
            os.path.splitext(os.path.basename(v_image.get().strip()))[0] + ".raw")
        if not output:
            return
        if os.path.exists(output):
            messagebox.showerror(TITLE, f"Refusing to overwrite an existing file:\n{output}")
            return
        start("export", output=output, entry=entry)

    def poll():
        try:
            while True:
                tag, line = lines.get_nowait()
                if line is None:
                    state["streams"] -= 1
                    continue
                match = PERCENT.search(line) if tag == "err" else None
                if match:
                    progress["value"] = float(match.group(1))
                    status["text"] = line.strip()
                elif tag == "out" and state["mode"] == "files":
                    if state["header"]:
                        state["header"] = False
                    elif line.strip():
                        table.insert("", "end", values=line.split("\t", 3))
                elif line.strip():
                    state["out"].append(line)
                    write(line + "\n")
        except queue.Empty:
            pass
        proc = state["proc"]
        if proc is not None and (proc.poll() is None or state["streams"] > 0):
            root.after(50, poll)
            return
        finish(proc.returncode if proc is not None else None)

    def finish(code):
        for button in actions:
            button["state"] = "normal"
        b_cancel["state"] = "disabled"
        state["proc"] = None
        if code == 0:
            progress["value"] = 100
            status["text"] = {"files": f"done: {len(table.get_children()):,} entries",
                              "verify": "done: see the hash lines"}.get(state["mode"], "done")
        elif code is None:
            status["text"] = "not started"
        elif code < 0:
            status["text"] = "cancelled"
        else:
            status["text"] = f"ewfprobe exited {code}"
        state["result"] = (code, "\n".join(state["out"]))
        if smoke:
            root.after(10, root.destroy)

    def cancel():
        proc = state["proc"]
        if proc is not None and proc.poll() is None:
            proc.terminate()
            write("\n[cancelled: an export stopped part way is not a complete copy]\n")

    b_info.configure(command=lambda: start("info"))
    b_verify.configure(command=lambda: start("verify"))
    b_files.configure(command=lambda: start("files"))
    b_export.configure(command=export)
    b_cancel.configure(command=cancel)

    def on_close():
        cancel()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    if smoke:
        v_image.set(smoke)
        root.after(100, lambda: start("verify"))
    root.mainloop()
    return state["result"]


def main(argv):
    if argv and argv[0] == "--cli":
        return run_cli(argv[1:])
    if argv and argv[0] == "--smoke":
        if len(argv) != 2:
            print("usage: ewfprobe_gui.py --smoke IMAGE", file=sys.stderr)
            return 2
        code, output = build_window(smoke=os.path.abspath(argv[1])) or (None, "")
        print(json.dumps({"exit": code, "output": output}))
        return 0 if code == 0 else 1
    build_window(os.path.abspath(argv[0]) if argv and os.path.exists(argv[0]) else "")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
