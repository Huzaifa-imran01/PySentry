"""Simple Tk desktop front end. Run with python -m src.gui."""
import json
from pathlib import Path
from queue import Empty, Queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

from src.gemini_provider import MODEL
from src.reporting import save_json
from src.gui_support import (PROJECT_ROOT, ScanOptions, as_dict, dict_rows,
                             load_report, overview_text, run_scan)


def replace_text(widget, text):
    widget.configure(state="normal")
    widget.delete("1.0", "end")
    widget.insert("1.0", text)
    widget.configure(state="disabled")


def detail_text(row):
    parts = []
    for key, value in row.items():
        label = key.replace("_", " ").capitalize()
        if isinstance(value, (dict, list)):
            value = json.dumps(value, indent=2, ensure_ascii=False)
        parts.append(f"{label}\n{value if value is not None else 'Not provided'}")
    return "\n\n".join(parts)


class DetailsTable(ttk.Frame):
    def __init__(self, parent, columns):
        super().__init__(parent)
        self.rows = {}
        pane = ttk.Panedwindow(self, orient="vertical")
        pane.pack(fill="both", expand=True)
        top = ttk.Frame(pane)
        top.rowconfigure(0, weight=1)
        top.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(top, columns=[c[0] for c in columns], show="headings", selectmode="browse", height=9)
        for key, title, width in columns:
            self.tree.heading(key, text=title)
            self.tree.column(key, width=width, minwidth=60, stretch=True)
        vertical = ttk.Scrollbar(top, orient="vertical", command=self.tree.yview)
        horizontal = ttk.Scrollbar(top, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal.grid(row=1, column=0, sticky="ew")
        bottom = ttk.LabelFrame(pane, text="Selected item — full details", padding=6)
        self.details = ScrolledText(bottom, wrap="word", height=10, font=("Consolas", 10), state="disabled")
        self.details.pack(fill="both", expand=True)
        pane.add(top, weight=3)
        pane.add(bottom, weight=2)
        self.tree.bind("<<TreeviewSelect>>", self.select)

    def populate(self, items):
        self.tree.delete(*self.tree.get_children())
        self.rows = {}
        for index, (values, data) in enumerate(items):
            iid = str(index)
            self.tree.insert("", "end", iid=iid, values=values)
            self.rows[iid] = data
        replace_text(self.details, "Select an item above to view its full message and evidence." if self.rows else "No items in this view. Check Overview for scan, AI, and dependency status.")
        if self.rows:
            self.tree.selection_set("0")
            self.select()

    def select(self, event=None):
        selected = self.tree.selection()
        if selected:
            replace_text(self.details, detail_text(self.rows[selected[0]]))


class ReviewApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Code Review Agent")
        self.root.geometry("1160x850")
        self.root.minsize(900, 720)
        self.events = Queue()
        self.busy = False
        self.close_when_done = False
        self.report = None
        self.target = tk.StringVar()
        self.key = tk.StringVar()
        self.model = tk.StringVar(value=MODEL)
        self.dependency_mode = tk.StringVar(value="Discover project manifests")
        self.dependency_input = tk.StringVar()
        self.search = tk.StringVar()
        self.severity = tk.StringVar(value="All severities")
        self.status = tk.StringVar(value="Ready. Choose a Python file or project folder.")
        self.summary = tk.StringVar(value="No report loaded")
        self.advanced_visible = tk.BooleanVar(value=False)
        self.fail_on = tk.StringVar(value="none")
        self.require_deps = tk.BooleanVar()
        self.profile = tk.StringVar(value="standard")
        self.secret_scope = tk.StringVar(value="directory")
        self.require_secrets = tk.BooleanVar()
        self.require_rules = tk.BooleanVar()
        self.limit_vars = {name: tk.StringVar(value=str(value)) for name, value in
                           (("max_file_bytes", 1000000), ("scanner_timeout", 120), ("max_files", 1000), ("total_timeout", 600))}
        self.inputs = []
        self.build()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(100, self.poll)

    def input_widget(self, widget):
        self.inputs.append(widget)
        return widget

    def build(self):
        shell = ttk.Frame(self.root, padding=14)
        shell.pack(fill="both", expand=True)
        heading = ttk.Frame(shell)
        heading.pack(fill="x", pady=(0, 10))
        ttk.Label(heading, text="Secure Code Review Agent", font=("Segoe UI", 18, "bold")).pack(side="left")
        self.open_button = self.input_widget(ttk.Button(heading, text="Open report…", command=self.open_report))
        self.open_button.pack(side="right")
        self.export_button = ttk.Button(heading, text="Export report…", command=self.export_report, state="disabled")
        self.export_button.pack(side="right", padx=8)

        options = ttk.LabelFrame(shell, text="Scan setup", padding=10)
        options.pack(fill="x")
        options.columnconfigure(1, weight=1)
        ttk.Label(options, text="File or folder").grid(row=0, column=0, sticky="w", padx=(0, 10))
        self.input_widget(ttk.Entry(options, textvariable=self.target)).grid(row=0, column=1, sticky="ew")
        self.input_widget(ttk.Button(options, text="Browse file…", command=self.choose_file)).grid(row=0, column=2, padx=5)
        self.input_widget(ttk.Button(options, text="Browse folder…", command=self.choose_folder)).grid(row=0, column=3)
        ttk.Label(options, text="Gemini API key").grid(row=1, column=0, sticky="w", pady=(8, 0))
        self.input_widget(ttk.Entry(options, textvariable=self.key, show="*")).grid(row=1, column=1, sticky="ew", pady=(8, 0))
        model_box = ttk.Frame(options)
        model_box.grid(row=1, column=2, columnspan=2, sticky="ew", padx=(5, 0), pady=(8, 0))
        ttk.Label(model_box, text="Model").pack(side="left", padx=(0, 5))
        self.input_widget(ttk.Entry(model_box, textvariable=self.model, width=23)).pack(side="left", fill="x", expand=True)
        ttk.Label(options, text="Optional: blank key means basic scanning. Gemini receives screened, masked source context; validation may incur a small charge.",
                  wraplength=980).grid(row=2, column=0, columnspan=4, sticky="w", pady=(5, 6))
        ttk.Label(options, text="Dependencies").grid(row=3, column=0, sticky="w")
        dependency_box = ttk.Frame(options)
        dependency_box.grid(row=3, column=1, columnspan=3, sticky="ew")
        dependency_box.columnconfigure(1, weight=1)
        self.dep_combo = self.input_widget(ttk.Combobox(dependency_box, textvariable=self.dependency_mode, state="readonly", width=27,
            values=("Discover project manifests", "Manifest file", "Installed packages folder", "Skip dependency audit")))
        self.dep_combo.grid(row=0, column=0, padx=(0, 8))
        self.dep_combo.bind("<<ComboboxSelected>>", self.dependency_changed)
        self.dep_entry = self.input_widget(ttk.Entry(dependency_box, textvariable=self.dependency_input))
        self.dep_entry.grid(row=0, column=1, sticky="ew")
        self.dep_browse = self.input_widget(ttk.Button(dependency_box, text="Browse…", command=self.choose_dependencies))
        self.dep_browse.grid(row=0, column=2, padx=(5, 0))
        self.dependency_changed()

        policy = ttk.Frame(options)
        policy.grid(row=4, column=0, columnspan=4, sticky="w", pady=(7, 0))
        ttk.Label(policy, text="Fail on severity").pack(side="left")
        self.policy_combo = self.input_widget(ttk.Combobox(policy, textvariable=self.fail_on,
            values=("none", "low", "medium", "high"), width=8, state="readonly"))
        self.policy_combo.pack(side="left", padx=6)
        for label, variable in (("Require dependency audit", self.require_deps), ("Require validated rules", self.require_rules)):
            self.input_widget(ttk.Checkbutton(policy, text=label, variable=variable)).pack(side="left")
        scope = ttk.Frame(options)
        scope.grid(row=5, column=0, columnspan=4, sticky="w")
        self.scope_combos = []
        for label, variable, values in (("Rule profile", self.profile, ("basic","standard","deep")),
                                        ("Secret scan", self.secret_scope, ("directory","history","off"))):
            ttk.Label(scope, text=label).pack(side="left")
            combo = self.input_widget(ttk.Combobox(scope, textvariable=variable, values=values, state="readonly", width=10))
            combo.pack(side="left", padx=6)
            self.scope_combos.append(combo)
        self.input_widget(ttk.Checkbutton(scope, text="Require secret scan", variable=self.require_secrets)).pack(side="left")
        controls = ttk.Frame(shell)
        controls.pack(fill="x", pady=9)
        self.scan_button = ttk.Button(controls, text="Start scan", command=self.start_scan)
        self.scan_button.pack(side="left")
        self.input_widget(ttk.Checkbutton(controls, text="Advanced limits", variable=self.advanced_visible, command=self.toggle_advanced)).pack(side="left", padx=14)
        self.progress = ttk.Progressbar(controls, mode="indeterminate", length=160)
        self.progress.pack(side="right")
        self.advanced = ttk.LabelFrame(shell, text="Existing scanner limits", padding=8)
        for index, (name, label) in enumerate((("max_file_bytes", "Max file bytes"), ("max_files", "Max files"),
                                               ("scanner_timeout", "Scanner timeout (s)"), ("total_timeout", "Source budget (s)"))):
            ttk.Label(self.advanced, text=label).grid(row=0, column=index*2, padx=(6, 4))
            self.input_widget(ttk.Entry(self.advanced, textvariable=self.limit_vars[name], width=10)).grid(row=0, column=index*2+1)
        self.summary_label = ttk.Label(shell, textvariable=self.summary, font=("Segoe UI", 10, "bold"), wraplength=1050)
        self.summary_label.pack(fill="x", pady=(2, 8))
        self.notebook = ttk.Notebook(shell)
        self.notebook.pack(fill="both", expand=True)
        self.overview = self.text_tab("Overview")
        replace_text(self.overview, "Choose a Python file or folder, optionally enter a Gemini key, then click Start scan.\n\nYou can also open an existing combined report.json.\n\nThe GUI uses the existing scanner unchanged.")

        finding_frame = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(finding_frame, text="Source findings")
        filter_bar = ttk.Frame(finding_frame)
        filter_bar.pack(fill="x", pady=(0, 6))
        ttk.Label(filter_bar, text="Search").pack(side="left", padx=(0, 5))
        ttk.Entry(filter_bar, textvariable=self.search).pack(side="left", fill="x", expand=True)
        ttk.Combobox(filter_bar, textvariable=self.severity, state="readonly", width=18,
                     values=("All severities", "HIGH", "MEDIUM", "LOW", "ERROR", "WARNING", "INFO", "UNKNOWN")).pack(side="left", padx=(8, 0))
        self.finding_table = DetailsTable(finding_frame, [("severity", "Severity", 85), ("scanner", "Scanner", 85),
            ("rule", "Rule", 190), ("file", "File", 260), ("line", "Line", 60), ("message", "Message", 350)])
        self.finding_table.pack(fill="both", expand=True)
        self.search.trace_add("write", self.filter_findings)
        self.severity.trace_add("write", self.filter_findings)
        self.issues_table = self.table_tab("Logical issues", [("category","Category",230),("severity","Severity",90),("evidence","Detections",80),("file","File",280),("line","Line",50)])
        self.secrets_table = self.table_tab("Secrets", [("detector","Detector",200),("scope","Scope",90),("file","File",280),("line","Line",50)])
        self.ai_table = self.table_tab("AI reviews", [("status", "Status", 95), ("rule", "Rule", 160),
            ("file", "File", 270), ("line", "Line", 55), ("fix", "Fix classification", 190), ("related", "Related findings", 110)])
        self.dep_table = self.table_tab("Dependency advisories", [("package", "Package", 180), ("version", "Version", 100),
            ("advisory", "Advisory", 240), ("fixed", "Fixed versions", 230)])
        self.coverage_table = self.table_tab("Files & coverage", [("status", "Status", 90), ("path", "Path", 430),
            ("reason", "Reason / scanner status", 430)])
        self.messages = self.text_tab("Messages")
        self.raw = self.text_tab("Raw report")
        ttk.Separator(shell).pack(fill="x", pady=(8, 5))
        ttk.Label(shell, textvariable=self.status, wraplength=1050).pack(fill="x")

    def text_tab(self, title):
        frame = ttk.Frame(self.notebook, padding=6)
        self.notebook.add(frame, text=title)
        text = ScrolledText(frame, wrap="word", font=("Consolas", 10), state="disabled")
        text.pack(fill="both", expand=True)
        return text

    def table_tab(self, title, columns):
        table = DetailsTable(self.notebook, columns)
        self.notebook.add(table, text=title)
        return table

    def choose_file(self):
        path = filedialog.askopenfilename(parent=self.root, title="Choose Python source", filetypes=[("Python files", "*.py"), ("All files", "*.*")])
        if path: self.target.set(path)

    def choose_folder(self):
        path = filedialog.askdirectory(parent=self.root, title="Choose project folder")
        if path: self.target.set(path)

    def dependency_changed(self, event=None):
        enabled = self.dependency_mode.get() in ("Manifest file", "Installed packages folder") and not self.busy
        self.dep_entry.configure(state="normal" if enabled else "disabled")
        self.dep_browse.configure(state="normal" if enabled else "disabled")

    def choose_dependencies(self):
        if self.dependency_mode.get() == "Installed packages folder":
            path = filedialog.askdirectory(parent=self.root, title="Choose target project's site-packages")
        else:
            path = filedialog.askopenfilename(parent=self.root, title="Choose requirements or lockfile", filetypes=[("Dependency manifests", "*.txt *.lock *.toml"), ("All files", "*.*")])
        if path: self.dependency_input.set(path)

    def toggle_advanced(self):
        if self.advanced_visible.get():
            self.advanced.pack(fill="x", pady=(0, 8), before=self.summary_label)
        else:
            self.advanced.pack_forget()

    def read_options(self):
        mode = self.dependency_mode.get()
        requirements = self.dependency_input.get().strip() if mode == "Manifest file" else ""
        installed = self.dependency_input.get().strip() if mode == "Installed packages folder" else ""
        if mode in ("Manifest file", "Installed packages folder") and not self.dependency_input.get().strip():
            raise ValueError("Choose the dependency input, or switch to automatic detection.")
        try:
            limits = {name: (int(var.get()) if name in ("max_file_bytes", "max_files") else float(var.get()))
                      for name, var in self.limit_vars.items()}
        except ValueError:
            raise ValueError("Scan limits must be numbers; file counts and byte sizes must be integers.") from None
        options = ScanOptions(self.target.get().strip(), self.model.get().strip(), mode == "Skip dependency audit", requirements, installed, **limits, fail_on=self.fail_on.get(),
                              profile=self.profile.get(), secrets=self.secret_scope.get(), require_secrets=self.require_secrets.get(), require_dependencies=self.require_deps.get(), require_validated_rules=self.require_rules.get())
        options.validate()
        return options

    def set_busy(self, busy):
        self.busy = busy
        for widget in self.inputs:
            widget.configure(state="disabled" if busy else "normal")
        if not busy:
            self.dep_combo.configure(state="readonly")
            self.policy_combo.configure(state="readonly")
            for combo in self.scope_combos:
                combo.configure(state="readonly")
        self.dependency_changed()
        self.scan_button.configure(state="disabled" if busy else "normal")
        self.export_button.configure(state="disabled" if busy or self.report is None else "normal")
        if busy: self.progress.start(12)
        else: self.progress.stop()

    def start_scan(self):
        if self.busy: return
        try:
            options = self.read_options()
        except ValueError as exc:
            messagebox.showerror("Check scan setup", str(exc), parent=self.root)
            return
        key = self.key.get().strip()
        self.key.set("")
        self.report = None
        for table in (self.finding_table, self.issues_table, self.secrets_table, self.ai_table, self.dep_table, self.coverage_table):
            table.populate([])
        for text in (self.overview, self.messages, self.raw): replace_text(text, "")
        self.summary.set("Scan in progress — results will appear when the scanner finishes.")
        self.status.set("Running existing scanner. Live progress and errors appear in Messages.")
        replace_text(self.overview, "Scanning…\nThe scanner validates a supplied Gemini key, scans the selected target, and writes its existing reports.")
        self.set_busy(True)
        self.notebook.select(self.messages.master.master)
        threading.Thread(target=run_scan, args=(options, key, self.events), daemon=False).start()

    def filter_findings(self, *args):
        if not hasattr(self, "finding_table"): return
        entries = dict_rows(as_dict(self.report).get("findings"))
        query = self.search.get().casefold()
        severity = self.severity.get()
        rows = []
        for item in entries:
            if severity != "All severities" and str(item.get("severity", "UNKNOWN")).upper() != severity: continue
            if query and query not in json.dumps(item, ensure_ascii=False).casefold(): continue
            values = (item.get("severity", "UNKNOWN"), item.get("scanner", ""), item.get("rule_id", ""),
                      item.get("file", ""), item.get("line", ""), item.get("message", ""))
            rows.append((values, item))
        self.finding_table.populate(rows)

    def display_report(self, report, path):
        self.report = report
        ai = as_dict(report.get("ai"))
        deps = as_dict(report.get("dependencies"))
        self.summary.set(f"Execution: {report.get('execution', {}).get('overall', 'unrecorded')} | Policy: {report.get('policy', {}).get('result', 'unrecorded')} | Source: {report.get('scan_status', '?')}   |   Logical issues: {len(report['logical_issues']) if 'logical_issues' in report else 'unrecorded'} | Detections: {len(report['findings'])} | Secrets: {report.get('secrets',{}).get('status','unrecorded')}   |   AI: {ai.get('status', '?')}   |   Dependencies: {deps.get('status', '?')}")
        replace_text(self.overview, overview_text(report))
        replace_text(self.raw, json.dumps(report, indent=2, ensure_ascii=False))
        self.filter_findings()
        self.issues_table.populate([((r["category"],r["normalized_severity"],len(r["evidence"]),r["evidence"][0]["file"],r["evidence"][0]["line"]),r) for r in dict_rows(report.get("logical_issues")) if r.get("evidence")])
        self.secrets_table.populate([((r["detector"],r["scope"],r["file"],r["line"]),r) for r in dict_rows(as_dict(report.get("secrets")).get("findings"))])
        ai_rows = []
        for row in dict_rows(ai.get("results")):
            finding = as_dict(row.get("finding"))
            details = dict(row)
            review = as_dict(row.get("review"))
            # Put readable explanations and unescaped multiline code before the full metadata.
            details = {**review, **details}
            ai_rows.append(((row.get("status", ""), finding.get("rule_id", ""), finding.get("file", ""),
                             finding.get("line", ""), row.get("fix_status", ""), len(dict_rows(row.get("related_findings")))), details))
        self.ai_table.populate(ai_rows)
        self.dep_table.populate([((row.get("package", ""), row.get("version", ""), row.get("advisory_id", ""),
                                  ", ".join(map(str, row.get("fixed_versions") or []))), row) for row in dict_rows(deps.get("findings"))])
        coverage = as_dict(report.get("coverage"))
        items = []
        for row in dict_rows(coverage.get("files")):
            reason = row.get("reason") or "; ".join(f"{k}: {v}" for k, v in as_dict(row.get("scanners")).items())
            items.append(((row.get("status", ""), row.get("path", ""), reason), row))
        for row in dict_rows(coverage.get("excluded")):
            items.append((("excluded", row.get("path", ""), row.get("reason", "")), row))
        self.coverage_table.populate(items)
        self.status.set("Report: " + str(path))
        self.notebook.select(self.overview.master.master)
        self.export_button.configure(state="normal" if not self.busy else "disabled")

    def poll(self):
        try:
            for _ in range(200):
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self.messages.configure(state="normal")
                    self.messages.insert("end", value)
                    self.messages.see("end")
                    self.messages.configure(state="disabled")
                elif kind == "finished":
                    self.set_busy(False)
                    if value["report"] is not None:
                        self.display_report(value["report"], value["path"])
                        if value["returncode"] == 1:
                            self.status.set("Security policy violation. See Overview for reasons.")
                        elif value["returncode"] == 2:
                            self.status.set(f"Scanner exited with code {value['returncode']}. Review incomplete coverage and Messages. Report: {value['path']}")
                    else:
                        self.summary.set("Scan did not produce a usable new report.")
                    if value["problem"]:
                        self.status.set(value["problem"])
                        if value["report"] is None:
                            replace_text(self.overview, value["problem"] + "\n\nSee Messages for details. Previous reports were not presented as new results.")
                    if self.close_when_done:
                        self.root.destroy()
                        return
        except Empty:
            pass
        self.root.after(100, self.poll)

    def open_report(self):
        if self.busy: return
        path = filedialog.askopenfilename(parent=self.root, initialdir=PROJECT_ROOT/"reports", title="Open combined scan report", filetypes=[("JSON reports", "*.json")])
        if not path: return
        try:
            self.display_report(load_report(path), path)
            replace_text(self.messages, "Opened a saved report. Live messages are available only for scans launched in this window.")
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror("Could not open report", str(exc), parent=self.root)

    def export_report(self):
        if self.report is None or self.busy: return
        path = filedialog.asksaveasfilename(parent=self.root, title="Export displayed report", defaultextension=".json", initialfile="security-review.json", filetypes=[("JSON report", "*.json")])
        if path:
            try:
                save_json(Path(path), self.report)
                self.status.set("Exported report: " + path)
            except OSError as exc:
                messagebox.showerror("Export failed", str(exc), parent=self.root)

    def close(self):
        if self.busy:
            if messagebox.askyesno("Scan in progress", "Close automatically when the scan finishes? The current scan will continue and save its report.", parent=self.root):
                self.close_when_done = True
                self.status.set("This window will close after the current scan finishes.")
            return
        self.root.destroy()


def main():
    root = tk.Tk()
    ttk.Style(root).configure("Treeview", rowheight=26)
    ReviewApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
