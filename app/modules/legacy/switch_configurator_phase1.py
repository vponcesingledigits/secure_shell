from __future__ import annotations

import json
import ipaddress
import tkinter as tk
from dataclasses import asdict, dataclass, field
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

APP_TITLE = "Switch Configurator - Phase 1"
APP_VERSION = "0.1"
PROJECT_EXTENSION = ".switchproj.json"


# ---------------------------------------------------------------------------
# Built-in defaults / profiles
# ---------------------------------------------------------------------------

BASE_DEFAULTS = {
    "vendor": "Ruckus ICX",
    "deployment_profile": "Marriott",
    "marsha_code": "",
    "property_name": "",
    "city": "",
    "state": "",
    "floor": "01",
    "closet": "IDF1",
    "switch_number": "001",
    "hostname": "",
    "model_family": "ICX7150",
    "model": "ICX7150-48P",
    "port_count": "48",
    "uplink_ports": "1/2/1 to 1/2/4",
    "uplink_speed_gbps": "10",
    "mgmt_vlan": "900",
    "mgmt_vlan_name": "MGMT",
    "mgmt_ip": "",
    "mgmt_mask": "255.255.255.248",
    "mgmt_gateway": "",
    "ap_vlan": "300",
    "highest_ap_port": "1/1/48",
    "timezone_offset": "-5",
    "loop_interval": "10",
    "loop_syslog_interval": "300",
    "loop_honeypot_vlan": "4094",
    "username": "admin",
    "password": "ChangeMe!",
    "snmp_community": "public",
    "snmp_contact": "Network Operations",
    "tacacs_secret": "SharedSecret123",
    "snmpv3_ro_auth": "roAuthPass123",
    "snmpv3_ro_priv": "roPrivPass123",
    "snmpv3_rw_auth": "rwAuthPass123",
    "snmpv3_rw_priv": "rwPrivPass123",
}

MARRIOTT_VLANS = [
    {"enabled": True, "vlan_id": "100", "name": "INTERCONNECT", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Core/uplink interconnect"},
    {"enabled": True, "vlan_id": "120", "name": "TRANSIT", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Transit / routed handoff"},
    {"enabled": True, "vlan_id": "200", "name": "PROPERTY-SERVERS", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Server segment"},
    {"enabled": True, "vlan_id": "201", "name": "PROPERTY-SERVERS2", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Server segment"},
    {"enabled": True, "vlan_id": "202", "name": "PROPERTY-SERVERS3", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Server segment"},
    {"enabled": True, "vlan_id": "203", "name": "PROPERTY-SERVERS4", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Server segment"},
    {"enabled": True, "vlan_id": "300", "name": "CLIENT", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "1/1/1 to 1/1/48", "notes": "Guest/AP access template"},
    {"enabled": True, "vlan_id": "301", "name": "CLIENT-AUX", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Aux client segment"},
    {"enabled": True, "vlan_id": "306", "name": "CLIENT-IOT", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "IoT / specialty clients"},
    {"enabled": True, "vlan_id": "399", "name": "SECURITY", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Security / NAC / monitoring"},
    {"enabled": True, "vlan_id": "450", "name": "WIRELESS-DEVICES", "subnet": "10.x.y+2.128/26", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Engineering override"},
    {"enabled": True, "vlan_id": "451", "name": "WIRELESS-DEVICES2", "subnet": "10.x.y+2.192/26", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Engineering override"},
    {"enabled": True, "vlan_id": "458", "name": "WIRELESS-IOT", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Wireless IoT"},
    {"enabled": True, "vlan_id": "900", "name": "MGMT", "subnet": "", "tagged": "1/2/1 to 1/2/4", "untagged": "", "notes": "Management"},
]

DEFAULT_PORTS = [
    {"enabled": True, "interface": "1/1/1", "description": "AP-01", "role": "AP"},
    {"enabled": True, "interface": "1/1/2", "description": "AP-02", "role": "AP"},
    {"enabled": True, "interface": "1/2/1", "description": "UPLINK-1", "role": "Uplink"},
]


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class VlanEntry:
    enabled: bool = True
    vlan_id: str = ""
    name: str = ""
    subnet: str = ""
    tagged: str = ""
    untagged: str = ""
    notes: str = ""


@dataclass
class PortEntry:
    enabled: bool = True
    interface: str = ""
    description: str = ""
    role: str = ""


@dataclass
class ProjectData:
    base: dict[str, str] = field(default_factory=lambda: dict(BASE_DEFAULTS))
    vlans: list[VlanEntry] = field(default_factory=lambda: [VlanEntry(**row) for row in MARRIOTT_VLANS])
    ports: list[PortEntry] = field(default_factory=lambda: [PortEntry(**row) for row in DEFAULT_PORTS])

    def to_json(self) -> str:
        payload = {
            "base": self.base,
            "vlans": [asdict(v) for v in self.vlans],
            "ports": [asdict(p) for p in self.ports],
        }
        return json.dumps(payload, indent=2)

    @classmethod
    def from_json(cls, raw: str) -> "ProjectData":
        data = json.loads(raw)
        project = cls()
        project.base = {**BASE_DEFAULTS, **data.get("base", {})}
        project.vlans = [VlanEntry(**row) for row in data.get("vlans", [])] or [VlanEntry(**row) for row in MARRIOTT_VLANS]
        project.ports = [PortEntry(**row) for row in data.get("ports", [])] or [PortEntry(**row) for row in DEFAULT_PORTS]
        return project


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def safe_upper(value: str) -> str:
    return (value or "").strip().upper()


def compute_hostname(base: dict[str, str]) -> str:
    marsha = safe_upper(base.get("marsha_code", ""))
    floor = str(base.get("floor", "")).strip()
    closet = safe_upper(base.get("closet", "IDF1"))
    sw_num = str(base.get("switch_number", "1")).strip().zfill(3)
    if not marsha:
        return ""
    return f"{marsha}SW{sw_num}-{floor}-{closet}"


def validate_ip(value: str) -> bool:
    if not value:
        return True
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def generate_snmp_location(base: dict[str, str]) -> str:
    parts = [base.get("property_name", ""), base.get("city", ""), base.get("state", ""), base.get("floor", ""), base.get("closet", "")]
    return " | ".join([p.strip() for p in parts if p and p.strip()])


def build_config_text(project: ProjectData) -> str:
    base = project.base
    hostname = base.get("hostname") or compute_hostname(base)
    lines: list[str] = []
    lines.append(f"! Generated by {APP_TITLE} {APP_VERSION}")
    lines.append(f"! Vendor: {base.get('vendor', '')}")
    lines.append(f"! Deployment Profile: {base.get('deployment_profile', '')}")
    lines.append("!")
    if hostname:
        lines.append(f"hostname {hostname}")
    if base.get("username") and base.get("password"):
        lines.append(f"username {base['username']} password {base['password']}")
    if base.get("mgmt_vlan"):
        lines.append(f"vlan {base['mgmt_vlan']} name {base.get('mgmt_vlan_name', 'MGMT')}")
    if base.get("mgmt_ip") and base.get("mgmt_mask"):
        lines.append(f"interface ve {base.get('mgmt_vlan', '')}")
        lines.append(f" ip address {base['mgmt_ip']} {base['mgmt_mask']}")
        if base.get("mgmt_gateway"):
            lines.append(f" ip default-gateway {base['mgmt_gateway']}")
        lines.append(" exit")
    if base.get("snmp_community"):
        lines.append(f"snmp-server community {base['snmp_community']} ro")
    if base.get("snmp_contact"):
        lines.append(f"snmp-server contact {base['snmp_contact']}")
    location = generate_snmp_location(base)
    if location:
        lines.append(f"snmp-server location {location}")
    if base.get("loop_interval"):
        lines.append(f"loop-detection interval {base['loop_interval']}")
    if base.get("loop_syslog_interval"):
        lines.append(f"loop-detection syslog interval {base['loop_syslog_interval']}")
    if base.get("loop_honeypot_vlan"):
        lines.append(f"loop-detection honeypot vlan {base['loop_honeypot_vlan']}")

    lines.append("!")
    lines.append("! VLAN Definitions")
    for vlan in project.vlans:
        if not vlan.enabled or not vlan.vlan_id:
            continue
        lines.append(f"vlan {vlan.vlan_id} name {vlan.name or 'VLAN-' + vlan.vlan_id}")
        if vlan.tagged:
            lines.append(f" tagged {vlan.tagged}")
        if vlan.untagged:
            lines.append(f" untagged {vlan.untagged}")
        if vlan.notes:
            lines.append(f" ! {vlan.notes}")
        lines.append(" exit")

    lines.append("!")
    lines.append("! Port Descriptions")
    for port in project.ports:
        if not port.enabled or not port.interface:
            continue
        lines.append(f"interface ethernet {port.interface}")
        if port.description:
            lines.append(f" port-name {port.description}")
        if port.role:
            lines.append(f" ! role: {port.role}")
        lines.append(" exit")

    lines.append("!")
    lines.append("end")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# GUI widgets
# ---------------------------------------------------------------------------

class SecretEntry(ttk.Frame):
    def __init__(self, master: tk.Widget, variable: tk.StringVar):
        super().__init__(master)
        self.variable = variable
        self._visible = False
        self.entry = ttk.Entry(self, textvariable=self.variable, show="*")
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.button = ttk.Button(self, text="Show", width=7, command=self.toggle)
        self.button.pack(side=tk.LEFT, padx=(6, 0))

    def toggle(self) -> None:
        self._visible = not self._visible
        self.entry.configure(show="" if self._visible else "*")
        self.button.configure(text="Hide" if self._visible else "Show")


class BaseConfigTab(ttk.Frame):
    FIELDS = [
        ("Vendor", "vendor", False),
        ("Deployment Profile", "deployment_profile", False),
        ("MARSHA Code", "marsha_code", False),
        ("Property Name", "property_name", False),
        ("City", "city", False),
        ("State", "state", False),
        ("Floor", "floor", False),
        ("Closet", "closet", False),
        ("Switch Number", "switch_number", False),
        ("Hostname Override", "hostname", False),
        ("Model Family", "model_family", False),
        ("Model", "model", False),
        ("Port Count", "port_count", False),
        ("Uplink Ports", "uplink_ports", False),
        ("Uplink Speed (Gbps)", "uplink_speed_gbps", False),
        ("Management VLAN", "mgmt_vlan", False),
        ("Management VLAN Name", "mgmt_vlan_name", False),
        ("Management IP", "mgmt_ip", False),
        ("Management Mask", "mgmt_mask", False),
        ("Management Gateway", "mgmt_gateway", False),
        ("AP VLAN", "ap_vlan", False),
        ("Highest AP Port", "highest_ap_port", False),
        ("Timezone Offset", "timezone_offset", False),
        ("Loop Detection Interval", "loop_interval", False),
        ("Loop Syslog Interval", "loop_syslog_interval", False),
        ("Loop Honeypot VLAN", "loop_honeypot_vlan", False),
        ("Username", "username", False),
        ("Password", "password", True),
        ("SNMP Community", "snmp_community", True),
        ("SNMP Contact", "snmp_contact", False),
        ("TACACS Secret", "tacacs_secret", True),
        ("SNMPv3 RO Auth", "snmpv3_ro_auth", True),
        ("SNMPv3 RO Priv", "snmpv3_ro_priv", True),
        ("SNMPv3 RW Auth", "snmpv3_rw_auth", True),
        ("SNMPv3 RW Priv", "snmpv3_rw_priv", True),
    ]

    def __init__(self, master: tk.Widget, base_vars: dict[str, tk.StringVar], on_change) -> None:
        super().__init__(master)
        self.base_vars = base_vars
        self.on_change = on_change
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)

        left = ttk.LabelFrame(self, text="Site / Switch Details")
        right = ttk.LabelFrame(self, text="Management / Credentials")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=6)
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=6)
        left.columnconfigure(1, weight=1)
        right.columnconfigure(1, weight=1)

        split_index = 18
        for row, (label_text, key, secret) in enumerate(self.FIELDS[:split_index]):
            self._build_field(left, row, label_text, key, secret)
        for row, (label_text, key, secret) in enumerate(self.FIELDS[split_index:]):
            self._build_field(right, row, label_text, key, secret)

        preview = ttk.LabelFrame(self, text="Derived Preview")
        preview.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))
        preview.columnconfigure(1, weight=1)
        ttk.Label(preview, text="Generated Hostname:").grid(row=0, column=0, sticky="w", padx=8, pady=6)
        self.hostname_preview = ttk.Label(preview, text="")
        self.hostname_preview.grid(row=0, column=1, sticky="w", padx=8, pady=6)
        ttk.Label(preview, text="SNMP Location:").grid(row=1, column=0, sticky="w", padx=8, pady=6)
        self.location_preview = ttk.Label(preview, text="")
        self.location_preview.grid(row=1, column=1, sticky="w", padx=8, pady=6)
        ttk.Button(preview, text="Reset to Defaults", command=self.reset_defaults).grid(row=0, column=2, rowspan=2, padx=8, pady=6)
        self.refresh_preview()

    def _build_field(self, parent: ttk.LabelFrame, row: int, label_text: str, key: str, secret: bool) -> None:
        ttk.Label(parent, text=label_text).grid(row=row, column=0, sticky="w", padx=8, pady=4)
        if secret:
            widget = SecretEntry(parent, self.base_vars[key])
            widget.grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        else:
            entry = ttk.Entry(parent, textvariable=self.base_vars[key])
            entry.grid(row=row, column=1, sticky="ew", padx=8, pady=4)
        self.base_vars[key].trace_add("write", self._trace_change)

    def _trace_change(self, *_args) -> None:
        self.refresh_preview()
        self.on_change()

    def refresh_preview(self) -> None:
        base = {k: v.get() for k, v in self.base_vars.items()}
        self.hostname_preview.configure(text=base.get("hostname") or compute_hostname(base) or "(not enough info)")
        self.location_preview.configure(text=generate_snmp_location(base) or "(not enough info)")

    def reset_defaults(self) -> None:
        for key, value in BASE_DEFAULTS.items():
            self.base_vars[key].set(value)


class EditableTableTab(ttk.Frame):
    def __init__(self, master: tk.Widget, columns: list[tuple[str, str, int]], add_callback, remove_callback):
        super().__init__(master)
        self.columns_meta = columns
        self.add_callback = add_callback
        self.remove_callback = remove_callback

        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, pady=(4, 6))
        ttk.Button(toolbar, text="Add Row", command=self.add_callback).pack(side=tk.LEFT)
        ttk.Button(toolbar, text="Remove Selected", command=self.remove_selected).pack(side=tk.LEFT, padx=6)

        col_ids = [c[0] for c in columns]
        self.tree = ttk.Treeview(self, columns=col_ids, show="headings", selectmode="browse")
        for col_id, title, width in columns:
            self.tree.heading(col_id, text=title)
            self.tree.column(col_id, width=width, anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<Double-1>", self._on_double_click)

    def remove_selected(self) -> None:
        item = self.tree.selection()
        if not item:
            return
        index = self.tree.index(item[0])
        self.remove_callback(index)

    def _on_double_click(self, event) -> None:
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        col_id = self.tree.identify_column(event.x)
        if not row_id or not col_id:
            return
        x, y, width, height = self.tree.bbox(row_id, col_id)
        value = self.tree.set(row_id, col_id)
        editor = ttk.Entry(self.tree)
        editor.insert(0, value)
        editor.place(x=x, y=y, width=width, height=height)
        editor.focus_set()

        def save_edit(_event=None):
            new_value = editor.get()
            self.tree.set(row_id, col_id, new_value)
            editor.destroy()
            self.event_generate("<<TableEdited>>")

        editor.bind("<Return>", save_edit)
        editor.bind("<FocusOut>", save_edit)


class PreviewTab(ttk.Frame):
    def __init__(self, master: tk.Widget):
        super().__init__(master)
        toolbar = ttk.Frame(self)
        toolbar.pack(fill=tk.X, pady=(4, 6))
        ttk.Label(toolbar, text="Rendered Configuration Preview").pack(side=tk.LEFT)
        self.text = tk.Text(self, wrap="none", font=("Consolas", 10))
        self.text.pack(fill=tk.BOTH, expand=True)
        x_scroll = ttk.Scrollbar(self, orient="horizontal", command=self.text.xview)
        y_scroll = ttk.Scrollbar(self, orient="vertical", command=self.text.yview)
        self.text.configure(xscrollcommand=x_scroll.set, yscrollcommand=y_scroll.set)
        x_scroll.pack(fill=tk.X, side=tk.BOTTOM)
        y_scroll.pack(fill=tk.Y, side=tk.RIGHT)

    def set_text(self, value: str) -> None:
        self.text.delete("1.0", tk.END)
        self.text.insert("1.0", value)


# ---------------------------------------------------------------------------
# Main App
# ---------------------------------------------------------------------------

class SwitchConfiguratorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1380x860")
        self.minsize(1100, 700)

        self.project = ProjectData()
        self.base_vars = {key: tk.StringVar(value=value) for key, value in self.project.base.items()}

        self._build_menu()
        self._build_layout()
        self.refresh_all_views()

    def _build_menu(self) -> None:
        menubar = tk.Menu(self)
        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="New Project", command=self.new_project)
        file_menu.add_command(label="Open Project...", command=self.open_project)
        file_menu.add_command(label="Save Project...", command=self.save_project)
        file_menu.add_separator()
        file_menu.add_command(label="Export Config...", command=self.export_config)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        profile_menu = tk.Menu(menubar, tearoff=False)
        profile_menu.add_command(label="Load Marriott Defaults", command=self.load_marriott_defaults)
        menubar.add_cascade(label="Profiles", menu=profile_menu)

        self.config(menu=menubar)

    def _build_layout(self) -> None:
        top = ttk.Frame(self, padding=8)
        top.pack(fill=tk.X)
        ttk.Label(top, text=APP_TITLE, font=("Segoe UI", 14, "bold")).pack(side=tk.LEFT)
        ttk.Label(top, text=f"Version {APP_VERSION}").pack(side=tk.LEFT, padx=(8, 0))
        self.status_label = ttk.Label(top, text="Ready")
        self.status_label.pack(side=tk.RIGHT)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.base_tab = BaseConfigTab(notebook, self.base_vars, self.on_base_changed)
        notebook.add(self.base_tab, text="Base Configuration")

        self.vlan_tab = EditableTableTab(
            notebook,
            columns=[
                ("enabled", "Enabled", 70),
                ("vlan_id", "VLAN ID", 80),
                ("name", "Name", 180),
                ("subnet", "Subnet / Notes", 160),
                ("tagged", "Tagged Ports", 180),
                ("untagged", "Untagged Ports", 180),
                ("notes", "Notes", 260),
            ],
            add_callback=self.add_vlan,
            remove_callback=self.remove_vlan,
        )
        self.vlan_tab.bind("<<TableEdited>>", lambda _e: self.on_vlan_table_changed())
        notebook.add(self.vlan_tab, text="VLAN Builder")

        self.port_tab = EditableTableTab(
            notebook,
            columns=[
                ("enabled", "Enabled", 70),
                ("interface", "Interface", 120),
                ("description", "Description", 250),
                ("role", "Role", 160),
            ],
            add_callback=self.add_port,
            remove_callback=self.remove_port,
        )
        self.port_tab.bind("<<TableEdited>>", lambda _e: self.on_port_table_changed())
        notebook.add(self.port_tab, text="Port Naming")

        self.preview_tab = PreviewTab(notebook)
        notebook.add(self.preview_tab, text="Preview")

        bottom = ttk.Frame(self, padding=(8, 0, 8, 8))
        bottom.pack(fill=tk.X)
        ttk.Button(bottom, text="Refresh Preview", command=self.refresh_preview).pack(side=tk.LEFT)
        ttk.Button(bottom, text="Save Project", command=self.save_project).pack(side=tk.LEFT, padx=6)
        ttk.Button(bottom, text="Export Config", command=self.export_config).pack(side=tk.LEFT)

    def set_status(self, text: str) -> None:
        self.status_label.configure(text=text)

    def get_project_from_ui(self) -> ProjectData:
        base = {key: var.get() for key, var in self.base_vars.items()}
        project = ProjectData(base=base)
        project.vlans = self._read_vlan_rows()
        project.ports = self._read_port_rows()
        return project

    def refresh_all_views(self) -> None:
        self._populate_vlan_table()
        self._populate_port_table()
        self.refresh_preview()

    def on_base_changed(self) -> None:
        self.set_status("Base configuration updated")

    def on_vlan_table_changed(self) -> None:
        self.set_status("VLAN table updated")
        self.refresh_preview()

    def on_port_table_changed(self) -> None:
        self.set_status("Port table updated")
        self.refresh_preview()

    def refresh_preview(self) -> None:
        self.project = self.get_project_from_ui()
        text = build_config_text(self.project)
        self.preview_tab.set_text(text)
        self.base_tab.refresh_preview()
        self._show_validation_status()

    def _show_validation_status(self) -> None:
        base = self.project.base
        issues: list[str] = []
        for field in ("mgmt_ip", "mgmt_gateway"):
            if base.get(field) and not validate_ip(base[field]):
                issues.append(f"Invalid {field.replace('_', ' ')}")
        if issues:
            self.set_status(" | ".join(issues))
        else:
            self.set_status("Ready")

    # --------------------------- VLAN table ---------------------------
    def _populate_vlan_table(self) -> None:
        tree = self.vlan_tab.tree
        for item in tree.get_children():
            tree.delete(item)
        for vlan in self.project.vlans:
            tree.insert("", tk.END, values=(
                "yes" if vlan.enabled else "no",
                vlan.vlan_id,
                vlan.name,
                vlan.subnet,
                vlan.tagged,
                vlan.untagged,
                vlan.notes,
            ))

    def _read_vlan_rows(self) -> list[VlanEntry]:
        rows: list[VlanEntry] = []
        for item in self.vlan_tab.tree.get_children():
            values = self.vlan_tab.tree.item(item, "values")
            rows.append(VlanEntry(
                enabled=str(values[0]).strip().lower() in {"yes", "true", "1", "y"},
                vlan_id=str(values[1]),
                name=str(values[2]),
                subnet=str(values[3]),
                tagged=str(values[4]),
                untagged=str(values[5]),
                notes=str(values[6]),
            ))
        return rows

    def add_vlan(self) -> None:
        self.vlan_tab.tree.insert("", tk.END, values=("yes", "", "", "", "", "", ""))
        self.refresh_preview()

    def remove_vlan(self, index: int) -> None:
        items = self.vlan_tab.tree.get_children()
        if 0 <= index < len(items):
            self.vlan_tab.tree.delete(items[index])
            self.refresh_preview()

    # --------------------------- Port table ---------------------------
    def _populate_port_table(self) -> None:
        tree = self.port_tab.tree
        for item in tree.get_children():
            tree.delete(item)
        for port in self.project.ports:
            tree.insert("", tk.END, values=(
                "yes" if port.enabled else "no",
                port.interface,
                port.description,
                port.role,
            ))

    def _read_port_rows(self) -> list[PortEntry]:
        rows: list[PortEntry] = []
        for item in self.port_tab.tree.get_children():
            values = self.port_tab.tree.item(item, "values")
            rows.append(PortEntry(
                enabled=str(values[0]).strip().lower() in {"yes", "true", "1", "y"},
                interface=str(values[1]),
                description=str(values[2]),
                role=str(values[3]),
            ))
        return rows

    def add_port(self) -> None:
        self.port_tab.tree.insert("", tk.END, values=("yes", "", "", ""))
        self.refresh_preview()

    def remove_port(self, index: int) -> None:
        items = self.port_tab.tree.get_children()
        if 0 <= index < len(items):
            self.port_tab.tree.delete(items[index])
            self.refresh_preview()

    # --------------------------- Project actions ---------------------------
    def new_project(self) -> None:
        self.project = ProjectData()
        for key, var in self.base_vars.items():
            var.set(self.project.base.get(key, ""))
        self.refresh_all_views()
        self.set_status("New project created")

    def load_marriott_defaults(self) -> None:
        self.project = self.get_project_from_ui()
        self.project.vlans = [VlanEntry(**row) for row in MARRIOTT_VLANS]
        self._populate_vlan_table()
        self.refresh_preview()
        self.set_status("Loaded Marriott VLAN defaults")

    def save_project(self) -> None:
        self.project = self.get_project_from_ui()
        filename = filedialog.asksaveasfilename(
            title="Save Project",
            defaultextension=PROJECT_EXTENSION,
            filetypes=[("Switch Project", f"*{PROJECT_EXTENSION}"), ("JSON", "*.json")],
        )
        if not filename:
            return
        Path(filename).write_text(self.project.to_json(), encoding="utf-8")
        self.set_status(f"Saved project to {filename}")

    def open_project(self) -> None:
        filename = filedialog.askopenfilename(
            title="Open Project",
            filetypes=[("Switch Project", f"*{PROJECT_EXTENSION}"), ("JSON", "*.json"), ("All Files", "*.*")],
        )
        if not filename:
            return
        try:
            self.project = ProjectData.from_json(Path(filename).read_text(encoding="utf-8"))
            for key, var in self.base_vars.items():
                var.set(self.project.base.get(key, ""))
            self.refresh_all_views()
            self.set_status(f"Opened project {filename}")
        except Exception as exc:
            messagebox.showerror("Open Failed", f"Could not open project file.\n\n{exc}")

    def export_config(self) -> None:
        self.project = self.get_project_from_ui()
        default_name = (self.project.base.get("hostname") or compute_hostname(self.project.base) or "switch_config") + ".txt"
        filename = filedialog.asksaveasfilename(
            title="Export Config",
            defaultextension=".txt",
            initialfile=default_name,
            filetypes=[("Text Config", "*.txt"), ("All Files", "*.*")],
        )
        if not filename:
            return
        Path(filename).write_text(build_config_text(self.project), encoding="utf-8")
        self.set_status(f"Exported config to {filename}")
        messagebox.showinfo("Export Complete", f"Configuration exported to:\n{filename}")


def main() -> None:
    app = SwitchConfiguratorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
