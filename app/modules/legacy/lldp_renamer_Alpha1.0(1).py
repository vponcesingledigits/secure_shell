import csv
import os
import re
import socket
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import paramiko


class PortNameTool:
    def __init__(self, root):
        self.root = root
        self.root.title("LLDP Port Naming Tool")
        self.root.geometry("1900x930")
        self.root.resizable(True, True)

        self.is_running = False
        self.active_workers = 0

        self.csv_path = tk.StringVar()
        self.input_mode = tk.StringVar(value="manual")
        self.show_password_var = tk.BooleanVar(value=False)
        self.skip_duplicates_var = tk.BooleanVar(value=True)
        self.skip_existing_named_var = tk.BooleanVar(value=True)

        self.manual_rows = []
        self.neighbor_occurrences = {}

        self.build_ui()

    def build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill="both", expand=True)

        source_frame = ttk.LabelFrame(main, text="Input Source", padding=10)
        source_frame.pack(fill="x", pady=(0, 8))

        ttk.Radiobutton(
            source_frame,
            text="Manual Entry",
            variable=self.input_mode,
            value="manual",
            command=self.update_input_mode,
        ).grid(row=0, column=0, sticky="w", padx=(0, 15))

        ttk.Radiobutton(
            source_frame,
            text="CSV Import",
            variable=self.input_mode,
            value="csv",
            command=self.update_input_mode,
        ).grid(row=0, column=1, sticky="w")

        manual_frame = ttk.LabelFrame(
            main,
            text="Manual Targets (Row 1 required, Rows 2–5 optional, later blank passwords reuse Row 1)",
            padding=10,
        )
        manual_frame.pack(fill="x", pady=(0, 8))
        self.manual_frame = manual_frame

        headers = ["IP Address *", "SSH Port", "Username *", "Password *"]
        for col, header in enumerate(headers):
            ttk.Label(manual_frame, text=header).grid(row=0, column=col, sticky="w", padx=4, pady=4)

        ttk.Checkbutton(
            manual_frame,
            text="Show all passwords",
            variable=self.show_password_var,
            command=self.toggle_all_passwords,
        ).grid(row=0, column=4, sticky="w", padx=8, pady=4)

        for i in range(5):
            ip_var = tk.StringVar()
            port_var = tk.StringVar(value="22")
            user_var = tk.StringVar()
            pass_var = tk.StringVar()

            ttk.Entry(manual_frame, textvariable=ip_var, width=24).grid(
                row=i + 1, column=0, padx=4, pady=4, sticky="ew"
            )
            ttk.Entry(manual_frame, textvariable=port_var, width=10).grid(
                row=i + 1, column=1, padx=4, pady=4, sticky="ew"
            )
            ttk.Entry(manual_frame, textvariable=user_var, width=18).grid(
                row=i + 1, column=2, padx=4, pady=4, sticky="ew"
            )

            pass_entry = ttk.Entry(manual_frame, textvariable=pass_var, width=18, show="*")
            pass_entry.grid(row=i + 1, column=3, padx=4, pady=4, sticky="ew")

            self.manual_rows.append(
                {
                    "ip_var": ip_var,
                    "port_var": port_var,
                    "user_var": user_var,
                    "pass_var": pass_var,
                    "pass_entry": pass_entry,
                }
            )

        csv_frame = ttk.LabelFrame(main, text="CSV Import", padding=10)
        csv_frame.pack(fill="x", pady=(0, 8))
        self.csv_frame = csv_frame

        ttk.Button(csv_frame, text="Browse CSV", command=self.browse_csv).grid(
            row=0, column=0, padx=(0, 8), pady=4
        )
        ttk.Entry(csv_frame, textvariable=self.csv_path, state="readonly", width=95).grid(
            row=0, column=1, sticky="ew", pady=4
        )
        ttk.Label(
            csv_frame,
            text="CSV columns: ip, port, username, password | line 1 password required, later blank passwords reuse line 1",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 0))
        csv_frame.columnconfigure(1, weight=1)

        controls = ttk.Frame(main)
        controls.pack(fill="x", pady=(0, 8))

        self.preview_button = ttk.Button(controls, text="Dry Run Preview", command=self.start_preview)
        self.preview_button.pack(side="left")

        self.push_button = ttk.Button(controls, text="Push Selected", command=self.start_push)
        self.push_button.pack(side="left", padx=(8, 0))

        ttk.Checkbutton(
            controls,
            text="Skip Duplicates During Push",
            variable=self.skip_duplicates_var,
        ).pack(side="left", padx=(12, 0))

        ttk.Checkbutton(
            controls,
            text="Skip Existing Named Ports",
            variable=self.skip_existing_named_var,
        ).pack(side="left", padx=(8, 0))

        ttk.Button(controls, text="Select All APs", command=self.select_all_aps).pack(side="left", padx=(16, 0))
        ttk.Button(controls, text="Select All Switches", command=self.select_all_switches).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Select Duplicates", command=self.select_duplicates).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Select LAGs", command=self.select_lags).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Select Needs Name", command=self.select_needs_name).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Select All", command=self.select_all_rows).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Clear Selection", command=self.clear_selection).pack(side="left", padx=(8, 0))
        ttk.Button(controls, text="Clear Table", command=self.clear_table).pack(side="left", padx=(16, 0))
        ttk.Button(controls, text="Clear Log", command=self.clear_log).pack(side="left", padx=(8, 0))

        table_frame = ttk.LabelFrame(main, text="Dry Run / Push Results", padding=10)
        table_frame.pack(fill="both", expand=True, pady=(0, 8))

        columns = (
            "hostname",
            "switch_ip",
            "local_port",
            "device_type",
            "neighbor_name",
            "switch_role",
            "link_direction",
            "is_lag",
            "existing_name",
            "proposed_name",
            "compare_result",
            "command_preview",
            "status",
        )

        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=21, selectmode="extended")

        headings = {
            "hostname": "Hostname",
            "switch_ip": "Switch IP",
            "local_port": "Local Port",
            "device_type": "Device Type",
            "neighbor_name": "Neighbor Name",
            "switch_role": "Switch Role",
            "link_direction": "Link Direction",
            "is_lag": "Is LAG",
            "existing_name": "Existing Name",
            "proposed_name": "Proposed Port Name",
            "compare_result": "Compare Result",
            "command_preview": "Command Preview",
            "status": "Status",
        }
        widths = {
            "hostname": 160,
            "switch_ip": 120,
            "local_port": 90,
            "device_type": 110,
            "neighbor_name": 260,
            "switch_role": 110,
            "link_direction": 110,
            "is_lag": 70,
            "existing_name": 150,
            "proposed_name": 240,
            "compare_result": 130,
            "command_preview": 360,
            "status": 140,
        }
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="center" if col == "is_lag" else "w")

        self.tree.tag_configure("ap", background="#e8f4ff")
        self.tree.tag_configure("switch", background="#e8ffe8")
        self.tree.tag_configure("duplicate", background="#ffd6d6")
        self.tree.tag_configure("unknown", background="#f2f2f2")
        self.tree.tag_configure("mismatch", background="#ffe7c2")
        self.tree.tag_configure("correct", background="#e6ffe6")
        self.tree.tag_configure("skipped_duplicate", background="#ffb3b3")
        self.tree.tag_configure("skipped_existing", background="#ffd9b3")
        self.tree.tag_configure("needs_name", background="#fff2cc")

        yscroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        xscroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll.grid(row=1, column=0, sticky="ew")

        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        log_frame = ttk.LabelFrame(main, text="Log Output", padding=10)
        log_frame.pack(fill="both", expand=False)
        self.log_text = tk.Text(log_frame, wrap="word", height=10)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_text.configure(yscrollcommand=log_scroll.set)

        self.update_input_mode()

    def update_input_mode(self):
        manual_state = "normal" if self.input_mode.get() == "manual" else "disabled"
        csv_state = "normal" if self.input_mode.get() == "csv" else "disabled"
        for child in self.manual_frame.winfo_children():
            try:
                child.configure(state=manual_state)
            except tk.TclError:
                pass
        for child in self.csv_frame.winfo_children():
            try:
                child.configure(state=csv_state)
            except tk.TclError:
                pass

    def toggle_all_passwords(self):
        show = "" if self.show_password_var.get() else "*"
        for row in self.manual_rows:
            row["pass_entry"].configure(show=show)

    def browse_csv(self):
        path = filedialog.askopenfilename(
            title="Select CSV File",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
        )
        if path:
            self.csv_path.set(path)

    def log(self, message):
        self.root.after(0, self._append_log, message)

    def _append_log(self, message):
        self.log_text.insert("end", message + "\n")
        self.log_text.see("end")

    def clear_log(self):
        self.log_text.delete("1.0", "end")

    def clear_table(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.neighbor_occurrences = {}

    def clear_selection(self):
        self.tree.selection_remove(*self.tree.selection())

    def select_all_rows(self):
        self.tree.selection_set(self.tree.get_children())

    def select_all_aps(self):
        self.tree.selection_remove(*self.tree.selection())
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            if values and str(values[3]).strip().lower() == "access point":
                self.tree.selection_add(item_id)

    def select_all_switches(self):
        self.tree.selection_remove(*self.tree.selection())
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            if values and str(values[3]).strip().lower() == "switch":
                self.tree.selection_add(item_id)

    def select_duplicates(self):
        self.tree.selection_remove(*self.tree.selection())
        for item_id in self.tree.get_children():
            if "duplicate" in self.tree.item(item_id, "tags"):
                self.tree.selection_add(item_id)

    def select_lags(self):
        self.tree.selection_remove(*self.tree.selection())
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            if values and str(values[7]).strip().lower() == "yes":
                self.tree.selection_add(item_id)

    def select_needs_name(self):
        self.tree.selection_remove(*self.tree.selection())
        for item_id in self.tree.get_children():
            values = self.tree.item(item_id, "values")
            if values and str(values[10]).strip().lower() == "needs name":
                self.tree.selection_add(item_id)

    def set_busy(self, busy=True):
        state = "disabled" if busy else "normal"
        self.preview_button.configure(state=state)
        self.push_button.configure(state=state)
        self.is_running = busy

    def validate_and_collect_targets(self):
        targets = []
        if self.input_mode.get() == "manual":
            row1 = self.manual_rows[0]
            row1_ip = row1["ip_var"].get().strip()
            row1_port = row1["port_var"].get().strip() or "22"
            row1_username = row1["user_var"].get().strip()
            row1_password = row1["pass_var"].get()

            if not row1_ip:
                messagebox.showerror("Input Error", "Manual row 1 requires an IP address.")
                return None
            if not row1_username:
                messagebox.showerror("Input Error", "Manual row 1 requires a username.")
                return None
            if not row1_password:
                messagebox.showerror("Input Error", "Manual row 1 requires a password.")
                return None

            try:
                socket.inet_aton(row1_ip)
                row1_port_int = int(row1_port)
                if not (1 <= row1_port_int <= 65535):
                    raise ValueError
            except OSError:
                messagebox.showerror("Input Error", f"Invalid IP address in manual row 1: {row1_ip}")
                return None
            except ValueError:
                messagebox.showerror("Input Error", f"Invalid SSH port in manual row 1: {row1_port}")
                return None

            targets.append({"ip": row1_ip, "port": row1_port_int, "username": row1_username, "password": row1_password})

            for index, row in enumerate(self.manual_rows[1:], start=2):
                ip = row["ip_var"].get().strip()
                raw_port = row["port_var"].get().strip()
                port = raw_port or "22"
                username = row["user_var"].get().strip()
                password = row["pass_var"].get()
                if not any([ip, raw_port, username, password]):
                    continue
                if not ip:
                    messagebox.showerror("Input Error", f"Manual row {index} is missing an IP address.")
                    return None
                if not username:
                    messagebox.showerror("Input Error", f"Manual row {index} is missing a username.")
                    return None
                if not password:
                    password = row1_password
                try:
                    socket.inet_aton(ip)
                    port_int = int(port)
                    if not (1 <= port_int <= 65535):
                        raise ValueError
                except OSError:
                    messagebox.showerror("Input Error", f"Invalid IP address in manual row {index}: {ip}")
                    return None
                except ValueError:
                    messagebox.showerror("Input Error", f"Invalid SSH port in manual row {index}: {port}")
                    return None
                targets.append({"ip": ip, "port": port_int, "username": username, "password": password})
        else:
            csv_file = self.csv_path.get().strip()
            if not csv_file:
                messagebox.showerror("Input Error", "Please choose a CSV file.")
                return None
            if not os.path.exists(csv_file):
                messagebox.showerror("Input Error", "Selected CSV file does not exist.")
                return None
            try:
                with open(csv_file, newline="", encoding="utf-8-sig") as f:
                    reader = csv.DictReader(f)
                    required = {"ip", "port", "username", "password"}
                    fieldnames = [h.strip() for h in (reader.fieldnames or [])]
                    if not required.issubset(set(fieldnames)):
                        messagebox.showerror("CSV Error", "CSV must contain columns: ip, port, username, password")
                        return None
                    records = list(reader)
                    if not records:
                        messagebox.showerror("CSV Error", "CSV file contains no usable rows.")
                        return None

                    first_record = records[0]
                    first_ip = (first_record.get("ip") or "").strip()
                    first_port = (first_record.get("port") or "").strip()
                    first_username = (first_record.get("username") or "").strip()
                    first_password = first_record.get("password") or ""
                    if not first_ip:
                        messagebox.showerror("CSV Error", "Missing IP on CSV line 2.")
                        return None
                    if not first_username:
                        messagebox.showerror("CSV Error", "Missing username on CSV line 2.")
                        return None
                    if not first_password:
                        messagebox.showerror("CSV Error", "CSV line 2 requires a password.")
                        return None
                    try:
                        socket.inet_aton(first_ip)
                        first_port_int = int(first_port)
                        if not (1 <= first_port_int <= 65535):
                            raise ValueError
                    except OSError:
                        messagebox.showerror("CSV Error", f"Invalid IP on CSV line 2: {first_ip}")
                        return None
                    except ValueError:
                        messagebox.showerror("CSV Error", f"Invalid port on CSV line 2: {first_port}")
                        return None
                    targets.append({"ip": first_ip, "port": first_port_int, "username": first_username, "password": first_password})

                    for offset, record in enumerate(records[1:], start=3):
                        ip = (record.get("ip") or "").strip()
                        port = (record.get("port") or "").strip()
                        username = (record.get("username") or "").strip()
                        password = record.get("password") or ""
                        if not ip:
                            messagebox.showerror("CSV Error", f"Missing IP on CSV line {offset}.")
                            return None
                        if not username:
                            messagebox.showerror("CSV Error", f"Missing username on CSV line {offset}.")
                            return None
                        if not password:
                            password = first_password
                        try:
                            socket.inet_aton(ip)
                            port_int = int(port or "22")
                            if not (1 <= port_int <= 65535):
                                raise ValueError
                        except OSError:
                            messagebox.showerror("CSV Error", f"Invalid IP on CSV line {offset}: {ip}")
                            return None
                        except ValueError:
                            messagebox.showerror("CSV Error", f"Invalid port on CSV line {offset}: {port}")
                            return None
                        targets.append({"ip": ip, "port": port_int, "username": username, "password": password})
            except Exception as exc:
                messagebox.showerror("CSV Error", str(exc))
                return None
        return targets

    def start_preview(self):
        if self.is_running:
            return
        targets = self.validate_and_collect_targets()
        if not targets:
            return
        self.clear_table()
        self.set_busy(True)
        self.active_workers = len(targets)
        self.log(f"Starting dry run preview for {len(targets)} target(s)")
        for target in targets:
            threading.Thread(target=self.preview_worker, args=(target,), daemon=True).start()

    def start_push(self):
        if self.is_running:
            return
        selected_ids = self.tree.selection()
        if not selected_ids:
            messagebox.showinfo("Nothing Selected", "Select one or more rows to push.")
            return

        groups = {}
        for item_id in selected_ids:
            row = self.tree.item(item_id, "values")
            if not row:
                continue
            compare_result = str(row[10]).strip().lower()
            existing_name = str(row[8]).strip()
            row_data = {
                "item_id": item_id,
                "hostname": row[0],
                "switch_ip": row[1],
                "local_port": row[2],
                "device_type": row[3],
                "neighbor_name": row[4],
                "switch_role": row[5],
                "link_direction": row[6],
                "is_lag": row[7],
                "existing_name": existing_name,
                "proposed_name": row[9],
                "compare_result": row[10],
                "command_preview": row[11],
                "status": row[12],
            }
            if self.skip_duplicates_var.get() and compare_result == "duplicate":
                self.update_row_status(item_id, "Skipped Duplicate")
                self.apply_tags(item_id, row_data)
                continue
            if self.skip_existing_named_var.get() and existing_name:
                self.update_row_status(item_id, "Skipped Existing")
                self.apply_tags(item_id, row_data)
                continue
            groups.setdefault(row[1], []).append(row_data)

        if not groups:
            messagebox.showinfo("Nothing To Push", "No rows remained after skip rules were applied.")
            return

        targets = self.validate_and_collect_targets()
        if not targets:
            return
        target_map = {t["ip"]: t for t in targets}

        self.set_busy(True)
        self.active_workers = 0
        for ip, rows in groups.items():
            target = target_map.get(ip)
            if not target:
                self.log(f"[{ip}] Not found in current target list, skipping push")
                continue
            self.active_workers += 1
            threading.Thread(target=self.push_selected_rows_worker, args=(target, rows), daemon=True).start()
        if self.active_workers == 0:
            self.set_busy(False)

    def preview_worker(self, target):
        ip = target["ip"]
        port = target["port"]
        username = target["username"]
        password = target["password"]
        timeout = 5
        try:
            self.log(f"[{ip}] Checking TCP connectivity")
            if not self.is_port_open(ip, port, timeout):
                self.log(f"[{ip}] SSH not available on port {port}")
                return

            ok_host, hostname = self.collect_hostname(ip, username, password, port, timeout)
            if not ok_host:
                self.log(f"[{ip}] Hostname failed: {hostname}")
                hostname = "UNKNOWN"

            ok_lldp, lldp_result = self.collect_lldp(ip, username, password, port, timeout)
            if not ok_lldp:
                self.log(f"[{ip}] LLDP failed: {lldp_result}")
                return

            ok_br, br_result = self.collect_interface_brief(ip, username, password, port, timeout)
            if not ok_br:
                self.log(f"[{ip}] show int br failed: {br_result}")
                return

            lldp_rows = self.parse_lldp_output(lldp_result)
            if not lldp_rows:
                self.log(f"[{ip}] No LLDP rows parsed")
                return

            existing_names = self.parse_interface_brief_names(br_result)
            count = 0
            for row in lldp_rows:
                proposed_name = self.build_port_name(row["neighbor_name"], row["device_type"], row["is_lag"])
                existing_name = existing_names.get(row["local_port"], "")
                compare_result = self.compare_names(existing_name, proposed_name)
                command_preview = f"int eth {row['local_port']} ; port-name {proposed_name}"
                display_row = {
                    "hostname": hostname,
                    "switch_ip": ip,
                    "local_port": row["local_port"],
                    "device_type": row["device_type"],
                    "neighbor_name": row["neighbor_name"],
                    "switch_role": row["switch_role"],
                    "link_direction": row["link_direction"],
                    "is_lag": row["is_lag"],
                    "existing_name": existing_name,
                    "proposed_name": proposed_name,
                    "compare_result": compare_result,
                    "command_preview": command_preview,
                    "status": "Previewed",
                }
                self.root.after(0, lambda r=display_row: self.add_row(r))
                count += 1
            self.log(f"[{ip}] Parsed {count} LLDP ports")
        except Exception as e:
            self.log(f"[{ip}] ERROR: {e}")
        finally:
            self.worker_done()

    def push_selected_rows_worker(self, target, config_rows):
        ip = target["ip"]
        port = target["port"]
        username = target["username"]
        password = target["password"]
        timeout = 5
        try:
            self.log(f"[{ip}] Pushing {len(config_rows)} selected change(s)")
            ok, msg = self.apply_port_names(ip, username, password, port, timeout, config_rows)
            status_text = "Pushed" if ok else "Failed"
            self.log(f"[{ip}] {'OK' if ok else 'FAILED'}: {msg}")
            for row in config_rows:
                self.root.after(0, self.update_row_status, row["item_id"], status_text)
        finally:
            self.worker_done()

    def worker_done(self):
        def finish():
            self.active_workers -= 1
            if self.active_workers <= 0:
                self.set_busy(False)
                self.log("All sessions complete.")
        self.root.after(0, finish)

    @staticmethod
    def is_port_open(host, port, timeout):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            return sock.connect_ex((host, port)) == 0
        except Exception:
            return False
        finally:
            sock.close()

    def collect_hostname(self, host, username, password, port, timeout):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            channel = client.invoke_shell()
            channel.settimeout(timeout)
            time.sleep(1)
            self._drain_channel(channel)
            channel.send("hostname\n")
            time.sleep(1)
            output = self._read_channel_until_quiet(channel, quiet_cycles=3)
            output = self.clean_output(output)
            hostname = self.parse_hostname(output)
            if not hostname:
                return False, "Could not parse hostname"
            return True, hostname
        except Exception as e:
            return False, str(e)
        finally:
            client.close()

    def collect_lldp(self, host, username, password, port, timeout):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            channel = client.invoke_shell()
            channel.settimeout(timeout)
            time.sleep(1)
            self._drain_channel(channel)
            for cmd in ["no page", "terminal length 0"]:
                channel.send(cmd + "\n")
                time.sleep(0.5)
                self._drain_channel(channel)
            channel.send("show lldp neighbor table\n")
            time.sleep(2)
            output = self._read_channel_until_quiet(channel, quiet_cycles=4, sleep_time=0.5)
            output = self.clean_output(output)
            if "Lcl Port" not in output and "System Name" not in output:
                channel.send("sh lldp nei\n")
                time.sleep(2)
                output = self._read_channel_until_quiet(channel, quiet_cycles=4, sleep_time=0.5)
                output = self.clean_output(output)
            if not output.strip():
                return False, "No output returned"
            return True, output
        except paramiko.AuthenticationException:
            return False, "Authentication failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            client.close()

    def collect_interface_brief(self, host, username, password, port, timeout):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            channel = client.invoke_shell()
            channel.settimeout(timeout)
            time.sleep(1)
            self._drain_channel(channel)
            channel.send("no page\n")
            time.sleep(0.5)
            self._drain_channel(channel)
            channel.send("terminal length 0\n")
            time.sleep(0.5)
            self._drain_channel(channel)
            channel.send("show int br\n")
            time.sleep(2)
            output = self._read_channel_until_quiet(channel, quiet_cycles=4, sleep_time=0.5)
            output = self.clean_output(output)
            if not output.strip():
                return False, "No output returned"
            return True, output
        except paramiko.AuthenticationException:
            return False, "Authentication failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            client.close()

    def apply_port_names(self, host, username, password, port, timeout, config_rows):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=timeout,
                auth_timeout=timeout,
                banner_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
            channel = client.invoke_shell()
            channel.settimeout(timeout)
            time.sleep(1)
            self._drain_channel(channel)
            commands = ["conf t"]
            for row in config_rows:
                commands.append(f"int eth {row['local_port']}")
                commands.append(f"port-name {row['proposed_name']}")
                commands.append("exit")
            commands.append("end")
            commands.append("write memory")
            for cmd in commands:
                self.log(f"[{host}] {cmd}")
                channel.send(cmd + "\n")
                time.sleep(0.35)
            self._read_channel_until_quiet(channel, quiet_cycles=5, sleep_time=0.5)
            return True, f"{len(config_rows)} port names pushed"
        except paramiko.AuthenticationException:
            return False, "Authentication failed"
        except paramiko.SSHException as e:
            return False, f"SSH error: {e}"
        except socket.timeout:
            return False, "Connection timed out"
        except Exception as e:
            return False, f"Error: {e}"
        finally:
            client.close()

    @staticmethod
    def _drain_channel(channel):
        output = ""
        while channel.recv_ready():
            output += channel.recv(65535).decode(errors="ignore")
        return output

    @staticmethod
    def _read_channel_until_quiet(channel, quiet_cycles=4, sleep_time=0.5):
        output = ""
        quiet_count = 0
        while quiet_count < quiet_cycles:
            if channel.recv_ready():
                output += channel.recv(65535).decode(errors="ignore")
                quiet_count = 0
            else:
                quiet_count += 1
                time.sleep(sleep_time)
        return output

    @staticmethod
    def clean_output(output):
        output = output.replace("\r", "")
        output = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", output)
        output = re.sub(r"--More--.*", "", output)
        return output

    @staticmethod
    def parse_hostname(output):
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower() == "hostname":
                continue
            if re.match(r"^[A-Za-z0-9._-]+$", line):
                return line
            m = re.search(r"@([A-Za-z0-9._-]+)#", line)
            if m:
                return m.group(1)
        return None

    def parse_lldp_output(self, output):
        rows = []
        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue
            line = re.sub(r"--More--.*", "", line).strip()
            if not line:
                continue
            lower = line.lower()
            if lower.startswith("ssh@") and "#" in lower:
                continue
            if lower in {"sh lldp nei", "show lldp neighbor table"}:
                continue
            if lower.startswith("lcl port"):
                continue
            if "chassis id" in lower and "system name" in lower:
                continue
            parsed = self.parse_lldp_line(line)
            if parsed:
                rows.append(parsed)
        return rows

    def parse_lldp_line(self, line):
        line = line.strip()
        port_match = re.match(r"^(?P<local_port>\d+/\d+/\d+|lg\d+|mgmt\d+|lag\d+)\s+", line, re.IGNORECASE)
        if not port_match:
            return None
        local_port = port_match.group("local_port")
        remainder = line[port_match.end():].strip()
        parts = re.split(r"\s{2,}", remainder)
        if len(parts) < 4:
            return None
        port_description = parts[2].strip() if len(parts) >= 3 else ""
        neighbor_name = " ".join(p.strip() for p in parts[3:] if p.strip())
        if not neighbor_name:
            return None
        device_type = self.classify_device(neighbor_name)
        switch_role = self.parse_switch_role(neighbor_name)
        link_direction = self.determine_link_direction(neighbor_name)
        is_lag = "Yes" if self.is_lag_candidate(device_type, neighbor_name, port_description) else "No"
        return {
            "local_port": local_port,
            "port_description": port_description,
            "neighbor_name": neighbor_name,
            "device_type": device_type,
            "switch_role": switch_role,
            "link_direction": link_direction,
            "is_lag": is_lag,
        }

    def parse_interface_brief_names(self, output):
        port_names = {}
        for raw_line in output.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                continue
            lower = line.lower().strip()
            if lower.startswith("ssh@") and "#" in lower:
                continue
            if lower in {"sh int br", "show int br"}:
                continue
            if lower.startswith("port       link") or lower.startswith("port "):
                continue
            first_token = line.split()[0] if line.split() else ""
            if not re.match(r"^(\d+/\d+/\d+|lg\d+|mgmt\d+|lag\d+)$", first_token, re.IGNORECASE):
                continue
            parts = re.split(r"\s{2,}", line.strip())
            if len(parts) < 10:
                continue
            port_id = parts[0].strip()
            existing_name = parts[10].strip() if len(parts) >= 11 else (parts[-1].strip() if len(parts) > 1 else "")
            if existing_name.lower() == "empty":
                existing_name = ""
            port_names[port_id] = existing_name
        return port_names

    @staticmethod
    def classify_device(name):
        upper = name.upper()
        if "AP" in upper:
            return "Access Point"
        if "SW" in upper or upper.startswith("RTR"):
            return "Switch"
        return "Unknown"

    @staticmethod
    def is_lag_candidate(device_type, neighbor_name, port_description=""):
        neighbor_upper = neighbor_name.upper()
        port_upper = port_description.upper()
        if device_type == "Switch":
            return True
        if "LAG" in neighbor_upper or "PORT-CHANNEL" in neighbor_upper:
            return True
        if "LAG" in port_upper or "PORT-CHANNEL" in port_upper:
            return True
        return False

    @staticmethod
    def parse_switch_role(neighbor_name):
        upper = (neighbor_name or "").upper()
        if "RTR-" in upper or upper.startswith("RTR"):
            return "RTR"
        if "MDF" in upper:
            return "MDF"
        idf_match = re.search(r"(IDF\d+|IDF)", upper)
        if idf_match:
            return idf_match.group(1)
        tail = upper.split("-")
        if len(tail) >= 3:
            last_part = tail[-1]
            if last_part not in {"MDF"} and not last_part.startswith("IDF"):
                return last_part[:10]
        return "SW"

    @staticmethod
    def determine_link_direction(neighbor_name):
        upper = (neighbor_name or "").upper()
        if "MDF" in upper:
            return "UL"
        if "IDF" in upper:
            return "DL"
        if "RTR-" in upper or upper.startswith("RTR"):
            return "UL"
        return "LINK"

    @staticmethod
    def build_port_name_from_lldp(neighbor_name):
        """
        Examples:
            SEAWIAP005-21-STower-2154 -> AP_005-STower_2154
            SEASW01-MDF -> SW_MDF
            SEASW03-IDF2 -> SW_IDF2
            RTR-ISP1 -> SW_RTR
        """
        upper = (neighbor_name or "").upper().strip()
        ap_match = re.search(r"AP(\d{1,4})", upper)
        if ap_match:
            ap_num = ap_match.group(1).zfill(3)
            parts = [p for p in upper.split("-") if p]
            building = ""
            room = ""
            if len(parts) >= 3:
                building = parts[-2].title().replace(" ", "")
                room = parts[-1]
            suffix = ""
            if building or room:
                suffix = f"-{building}_{room}".rstrip("_")
            return f"AP_{ap_num}{suffix}"
        if upper.startswith("RTR") or "RTR-" in upper:
            return "SW_RTR"
        if "MDF" in upper:
            return "SW_MDF"
        idf_match = re.search(r"(IDF\d+|IDF)", upper)
        if idf_match:
            return f"SW_{idf_match.group(1)}"
        tail = [p for p in upper.split("-") if p]
        if tail:
            return f"SW_{tail[-1][:16]}"
        return "NEIGHBOR"

    def build_port_name(self, neighbor_name, device_type, is_lag):
        base = self.build_port_name_from_lldp(neighbor_name)
        if device_type == "Switch" and is_lag == "Yes" and not base.endswith("_LAG"):
            return f"{base}_LAG"
        return base

    def compare_names(self, existing_name, proposed_name):
        existing = (existing_name or "").strip()
        proposed = (proposed_name or "").strip()
        if not existing:
            return "Needs Name"
        if existing.lower() == proposed.lower():
            return "Correct"
        if existing.lower().startswith(proposed.lower()) or proposed.lower().startswith(existing.lower()):
            return "Similar"
        if existing.lower() == "empty":
            return "Needs Name"
        return "Mismatch"

    def add_row(self, row):
        key = row["neighbor_name"].strip().upper()
        self.neighbor_occurrences[key] = self.neighbor_occurrences.get(key, 0) + 1
        item_id = self.tree.insert(
            "",
            "end",
            values=(
                row["hostname"], row["switch_ip"], row["local_port"], row["device_type"], row["neighbor_name"],
                row["switch_role"], row["link_direction"], row["is_lag"], row["existing_name"], row["proposed_name"],
                row["compare_result"], row["command_preview"], row["status"],
            ),
        )
        self.apply_tags(item_id, row)

    def update_row_status(self, item_id, status):
        values = list(self.tree.item(item_id, "values"))
        if not values:
            return
        values[12] = status
        self.tree.item(item_id, values=values)
        row = {
            "hostname": values[0], "switch_ip": values[1], "local_port": values[2], "device_type": values[3],
            "neighbor_name": values[4], "switch_role": values[5], "link_direction": values[6], "is_lag": values[7],
            "existing_name": values[8], "proposed_name": values[9], "compare_result": values[10],
            "command_preview": values[11], "status": values[12],
        }
        self.apply_tags(item_id, row)

    def apply_tags(self, item_id, row):
        tags = []
        device_type = str(row.get("device_type", "")).strip().lower()
        compare_result = str(row.get("compare_result", "")).strip().lower()
        status = str(row.get("status", "")).strip().lower()
        key = str(row.get("neighbor_name", "")).strip().upper()
        if device_type == "access point":
            tags.append("ap")
        elif device_type == "switch":
            tags.append("switch")
        else:
            tags.append("unknown")
        if self.neighbor_occurrences.get(key, 0) > 1:
            tags.append("duplicate")
        if compare_result == "mismatch":
            tags.append("mismatch")
        elif compare_result == "correct":
            tags.append("correct")
        elif compare_result == "needs name":
            tags.append("needs_name")
        if status == "skipped duplicate":
            tags.append("skipped_duplicate")
        if status == "skipped existing":
            tags.append("skipped_existing")
        self.tree.item(item_id, tags=tuple(tags))


def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    PortNameTool(root)
    root.mainloop()


if __name__ == "__main__":
    main()
