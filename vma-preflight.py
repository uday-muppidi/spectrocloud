#!/usr/bin/env python3
"""
Palette VMO / VMA (VM Migration Assistant) environment pre-flight checker.

Three modes, chosen interactively (no flags) or via --run:

  preflight  A/B/C/D/E : vCenter auth, VMA-required vCenter privileges,
                        ESXi discovery, DNS + TCP 443/902 reachability.
  allvms     F/G       : Per-VM vSphere-side checks required for virt-v2v:
                        vCenter version, guest OS support, VMware Tools,
                        snapshots, Secure Boot + PXE boot order, CD-ROM /
                        disk / RDM / IDE, NIC port groups + VLAN.
  windows    H         : Per-Windows-VM in-guest checks + optional
                        pre-migration prep via WinRM: Basic vs Dynamic
                        disks, Secure Boot state, hibernation off, Fast
                        Startup off, clean guest shutdown, vSphere power
                        state verification.
  all                  : preflight + allvms + windows.

Changes to a Windows guest (hibernation off, guest shutdown) are DRY-RUN by
default. Pass --apply to actually make them.

Usage examples:

  # Interactive menu
  python vma-preflight.py

  # Original preflight (unchanged)
  python vma-preflight.py --run preflight \\
      --vcenter vcenter.corp.example.com --user svc-vma@vsphere.local \\
      --vm web-01 --vm db-02 --insecure

  # All-VMs vSphere checks
  python vma-preflight.py --run allvms \\
      --vcenter vcenter.corp.example.com --user svc-vma@vsphere.local \\
      --vm web-01 --vm db-02 --insecure

  # Windows pre-migration prep (dry-run)
  python vma-preflight.py --run windows \\
      --vcenter vcenter.corp.example.com --user svc-vma@vsphere.local \\
      --vm win-01 --win-user Administrator --insecure

  # Same, actually apply the changes
  python vma-preflight.py --run windows --apply \\
      --vcenter vcenter.corp.example.com --user svc-vma@vsphere.local \\
      --vm win-01 --win-user Administrator --insecure

Exit status: 0 if all checks pass, 1 if any FAIL.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse
from pyVmomi import vim, vmodl
from pyVim.connect import SmartConnect, Disconnect


# ---------------------------------------------------------------------------
# Colored output helpers
# ---------------------------------------------------------------------------
class C:
    _tty = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
    RED = "\033[31m" if _tty else ""
    GRN = "\033[32m" if _tty else ""
    YLW = "\033[33m" if _tty else ""
    CYN = "\033[36m" if _tty else ""
    MAG = "\033[35m" if _tty else ""
    BLD = "\033[1m" if _tty else ""
    RST = "\033[0m" if _tty else ""


RESULTS: List[Tuple[str, str, str, str]] = []
_section = ""


def _record(name: str, status: str, detail: str = "") -> None:
    RESULTS.append((_section, name, status, detail))
    tag = {
        "PASS": f"✅ {C.GRN}[PASS]{C.RST}",
        "FAIL": f"❌ {C.RED}[FAIL]{C.RST}",
        "WARN": f"⚠  {C.YLW}[WARN]{C.RST}",
        "SKIP": f"⏭️ {C.CYN}[SKIP]{C.RST}",
        "PLAN": f"🚧 {C.MAG}[PLAN]{C.RST}",
        "DONE": f"⚡ {C.GRN}[DONE]{C.RST}",
    }[status]
    line = f"  {tag} {name}"
    if detail:
        line += f"  — {detail}"
    print(line)


def PASS(name: str, detail: str = "") -> None: _record(name, "PASS", detail)
def FAIL(name: str, detail: str = "") -> None: _record(name, "FAIL", detail)
def WARN(name: str, detail: str = "") -> None: _record(name, "WARN", detail)
def SKIP(name: str, detail: str = "") -> None: _record(name, "SKIP", detail)
def PLAN(name: str, detail: str = "") -> None: _record(name, "PLAN", detail)  # dry-run "would do"
def DONE(name: str, detail: str = "") -> None: _record(name, "DONE", detail)  # applied change


def head(name: str) -> None:
    global _section
    _section = name
    print(f"\n{C.BLD}== {name} =={C.RST}")


# ---------------------------------------------------------------------------
# VMA-required vCenter privileges (docs: Create Source Providers prerequisites)
# ---------------------------------------------------------------------------
VMA_REQUIRED_PRIVILEGES: Dict[str, str] = {
    "VirtualMachine.Interact.AnswerQuestion":       "Interaction > Answer question",
    "VirtualMachine.Interact.Backup":               "Interaction > Backup operation on virtual machine",
    "VirtualMachine.Interact.SetCDMedia":           "Interaction > Configure CD media",
    "VirtualMachine.Interact.SetFloppyMedia":       "Interaction > Configure floppy media",
    "VirtualMachine.Interact.ConsoleInteract":      "Interaction > Console interaction",
    "VirtualMachine.Interact.CreateScreenshot":     "Interaction > Create screenshot",
    "VirtualMachine.Interact.DefragmentAllDisks":   "Interaction > Defragment all disks",
    "VirtualMachine.Interact.DeviceConnection":     "Interaction > Device connection",
    "VirtualMachine.Interact.DnD":                  "Interaction > Drag and Drop",
    "VirtualMachine.Interact.GuestControl":         "Interaction > Guest operating system management by VIX API",
    "VirtualMachine.Interact.PutUsbScanCodes":      "Interaction > Inject USB HID scan codes",
    "VirtualMachine.Interact.Pause":                "Interaction > Pause or Unpause",
    "VirtualMachine.Interact.SESparseMaintenance":  "Interaction > Perform wipe or shrink operations",
    "VirtualMachine.Interact.PowerOff":             "Interaction > Power Off",
    "VirtualMachine.Interact.PowerOn":              "Interaction > Power On",
    "VirtualMachine.Interact.Record":               "Interaction > Record session on Virtual Machine",
    "VirtualMachine.Interact.Replay":               "Interaction > Replay session on Virtual Machine",
    "VirtualMachine.Interact.Reset":                "Interaction > Reset",
    "VirtualMachine.Interact.EnableSecondary":      "Interaction > Resume Fault Tolerance",
    "VirtualMachine.Interact.Suspend":              "Interaction > Suspend",
    "VirtualMachine.Interact.DisableSecondary":     "Interaction > Suspend Fault Tolerance / Test restart Secondary VM",
    "VirtualMachine.Interact.SuspendToMemory":      "Interaction > Suspend to memory",
    "VirtualMachine.Interact.MakePrimary":          "Interaction > Test failover",
    "VirtualMachine.Interact.TurnOffFaultTolerance": "Interaction > Turn Off Fault Tolerance",
    "VirtualMachine.Interact.CreateSecondary":      "Interaction > Turn On Fault Tolerance",
    "VirtualMachine.Interact.ToolsInstall":         "Interaction > VMware Tools install",
    "VirtualMachine.State.CreateSnapshot":          "Snapshot management > Create snapshot",
    "VirtualMachine.State.RemoveSnapshot":          "Snapshot management > Remove Snapshot",
}


# ---------------------------------------------------------------------------
# virt-v2v guest OS support (guestId prefixes vCenter can report)
# ---------------------------------------------------------------------------
# Broadly supported by virt-v2v (kernel-level virtio + libguestfs inspection).
V2V_SUPPORTED_GUESTID_PREFIXES: Tuple[str, ...] = (
    # RHEL family
    "rhel4", "rhel5", "rhel6", "rhel7", "rhel8", "rhel9", "rhel10",
    "centos", "centos6", "centos7", "centos8", "centos9",
    "oracleLinux", "oracleLinux6", "oracleLinux7", "oracleLinux8", "oracleLinux9",
    "almalinux", "rockylinux",
    # SUSE
    "sles11", "sles12", "sles13", "sles14", "sles15", "sles16",
    "opensuse",
    # Debian / Ubuntu
    "debian10", "debian11", "debian12",
    "ubuntu",
    # Fedora
    "fedora",
    # Windows (Server + client) that virt-v2v handles well
    "windows7", "windows8", "windows9",
    "windows2019", "windows2022", "windows2025",
    "windows11", "windows12",
    "windowsHyperVGuest",
)
# Explicitly not supported (very old or off-list OSes).
V2V_UNSUPPORTED_GUESTID_PREFIXES: Tuple[str, ...] = (
    "winXP", "winNT", "winNet", "win2000", "win98", "win95", "win31",
    "solaris", "freebsd", "netware", "darwin", "os2", "eComStation",
    "otherLinux", "other", "other24xLinux", "other26xLinux", "other3xLinux",
)

# ---------------------------------------------------------------------------
# vCenter version -> virt-v2v compatibility (SpectroCloud VMA: 7.0 / 8.0)
# ---------------------------------------------------------------------------
def vcenter_version_ok_for_v2v(api_version: str) -> Tuple[str, str]:
    m = re.match(r"^(\d+)\.(\d+)", api_version or "")
    if not m:
        return "WARN", f"unable to parse vCenter API version '{api_version}'"
    major = int(m.group(1))
    if major in (7, 8):
        return "PASS", f"vCenter {api_version} is supported (VMA requires vSphere 7.0 or 8.0)"
    if major >= 9:
        return "WARN", (
            f"vCenter {api_version} is newer than what SpectroCloud has verified for VMA "
            f"(vSphere 7.0 / 8.0). Migrations may work but are not officially verified."
        )
    return "FAIL", (
        f"vCenter {api_version} is older than the VMA-supported minimum (vSphere 7.0). "
        f"Upgrade vCenter/ESXi before attempting migration."
    )


# ---------------------------------------------------------------------------
# Endpoint parsing
# ---------------------------------------------------------------------------
def load_vm_file(path: str) -> Tuple[List[str], Optional[str]]:
    """Read VM names from a file, one per line.

    - Blank lines and lines whose first non-whitespace character is '#' are ignored.
    - Trailing '#' comments on a line are stripped ('web-01  # frontend' -> 'web-01').
    - Duplicates within the file are collapsed (first occurrence wins).

    Returns (names, error). On success, error is None.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        return [], f"cannot read --vm-file '{path}': {e}"

    seen: Dict[str, None] = {}
    for lineno, line in enumerate(raw.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            stripped = stripped.split("#", 1)[0].strip()
            if not stripped:
                continue
        # A VM name shouldn't contain whitespace; take the first token defensively.
        name = stripped.split()[0]
        if name and name not in seen:
            seen[name] = None
    return list(seen.keys()), None


def parse_endpoint(endpoint: str) -> Tuple[str, int]:
    endpoint = endpoint.strip()
    if "://" in endpoint:
        p = urlparse(endpoint)
        host = p.hostname or ""
        port = p.port or (443 if (p.scheme or "https").lower() == "https" else 80)
    elif endpoint.count(":") == 1:
        host, port_s = endpoint.split(":", 1)
        port = int(port_s)
    else:
        host, port = endpoint, 443
    if not host:
        raise ValueError(f"Could not parse host from endpoint: {endpoint!r}")
    return host, port


# ---------------------------------------------------------------------------
# vCenter connection helper (shared by preflight / allvms / windows modes)
# ---------------------------------------------------------------------------
def connect_vcenter(host, port, user, password, insecure, timeout):
    ssl_ctx = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(timeout, 15.0))
    try:
        si = SmartConnect(
            host=host, user=user, pwd=password, port=port,
            sslContext=ssl_ctx,
            connectionPoolTimeout=int(max(timeout, 15.0)),
        )
        return si, None
    except vim.fault.InvalidLogin:
        return None, "invalid login (user/password rejected)"
    except socket.gaierror as e:
        return None, f"DNS/host error: {e}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return None, f"network error: {e}"
    except ssl.SSLError as e:
        return None, f"TLS error: {e}. If vCenter uses a self-signed cert, re-run with --insecure."
    except vmodl.MethodFault as e:
        return None, f"vCenter API error: {e.msg}"
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"
    finally:
        socket.setdefaulttimeout(old_timeout)


def find_vm(content, name):
    view = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True
    )
    try:
        for vm in view.view:
            if vm.name == name:
                return vm
    finally:
        view.Destroy()
    return None


def find_inventory_object(content, path: str):
    """Resolve a vSphere inventory path to a managed object.

    Accepts:
      - Full inventory paths like 'MyDC/vm/Production' (VM folder subtree),
        'MyDC/host/MyCluster', or just 'MyDC' (Datacenter).
      - A bare Folder / Datacenter / ClusterComputeResource name; the first
        matching object in inventory wins.

    Returns the managed object (Folder, Datacenter, ClusterComputeResource,
    HostSystem, ResourcePool, ...) or None if nothing matched.
    """
    # 1) Exact inventory path lookup (fastest / most specific)
    try:
        obj = content.searchIndex.FindByInventoryPath(path)
        if obj is not None:
            return obj
    except Exception:
        pass

    # 2) Fallback: scan for a Folder / Datacenter / Cluster whose .name matches
    for kinds in ([vim.Folder], [vim.Datacenter], [vim.ClusterComputeResource]):
        view = content.viewManager.CreateContainerView(content.rootFolder, kinds, True)
        try:
            for obj in view.view:
                if getattr(obj, "name", None) == path:
                    return obj
        finally:
            view.Destroy()
    return None


def _describe_object(obj) -> str:
    """Short 'Type name' string for printing, e.g. 'Folder Production'."""
    cls = type(obj).__name__.replace("vim.", "")
    return f"{cls} '{getattr(obj, 'name', '?')}'"


def _inventory_path_of(obj) -> str:
    """Walk parent chain to build a human-readable vSphere inventory path.
    Returns something like 'MyDC/vm/Production/web-01'. Falls back to .name."""
    try:
        parts: List[str] = []
        cur = obj
        safety = 32
        while cur is not None and safety > 0:
            name = getattr(cur, "name", None)
            if not name:
                break
            parts.append(name)
            cur = getattr(cur, "parent", None)
            safety -= 1
        # Trim the top-most "Datacenters" root folder that vSphere adds.
        if parts and parts[-1].lower() in ("datacenters", "vcenter"):
            parts.pop()
        return "/".join(reversed(parts)) or getattr(obj, "name", "?")
    except Exception:
        return getattr(obj, "name", "?")


def _get_vm_parent_folder(vm):
    """Walk up from a VM to its nearest Folder parent (skipping vApp etc.)."""
    cur = getattr(vm, "parent", None)
    while cur is not None:
        if isinstance(cur, vim.Folder):
            return cur
        cur = getattr(cur, "parent", None)
    return None


# ===========================================================================
# MODE 1 - PREFLIGHT (existing checks A/B/C/D/E)
# ===========================================================================
def check_vcenter_preflight(
    host, port, user, password, insecure, vm_names, timeout,
    folder_paths=None, per_vm_privs=False,
) -> Optional[List[str]]:

    head("A. vCenter connectivity & authentication")
    si, err = connect_vcenter(host, port, user, password, insecure, timeout)
    if err:
        FAIL(f"Connect to {host}:{port}", err)
        return None
    PASS(f"Authenticated to vCenter {host}:{port} as {user}")

    try:
        content = si.RetrieveContent()
        about = content.about
        PASS("vCenter info", f"{about.fullName} (API {about.apiVersion}, {about.osType})")
    except Exception as e:  # noqa: BLE001
        WARN("Fetch vCenter about info", f"{type(e).__name__}: {e}")
        content = si.RetrieveContent()

    head("B. vCenter privileges required by VMA")
    _check_privileges(content, vm_names, folder_paths, per_vm_privs)

    head("C. ESXi host discovery (for VMs to migrate)")
    esxi_hosts = _discover_esxi_hosts(content, vm_names)

    try:
        Disconnect(si)
    except Exception:
        pass
    return esxi_hosts


def _check_privileges(content, vm_names, folder_paths=None, per_vm_privs=False):
    """Check VMA-required privileges, folder-first.

    Entity selection (in order):
      1) Explicit --folder paths, if any.
      2) Else: auto-infer the parent Folder of each --vm NAME (deduped).
      3) Else: vCenter root folder.

    When --per-vm-privs is also set, VMs are additionally checked individually
    (useful for diagnosing broken propagation on specific VMs).

    Entities with identical 'missing privileges' sets are collapsed into a
    single output group so a role gap shared by N VMs lists the gap ONCE.
    """

    auth_mgr = content.authorizationManager
    session_mgr = content.sessionManager
    try:
        session = session_mgr.currentSession
        user = session.userName
        session_key = session.key
    except Exception as e:  # noqa: BLE001
        FAIL("Fetch current session", str(e))
        return False
    PASS("Authenticated principal", user)

    # ---------- Build entity list ----------
    entities: List[Tuple[str, object]] = []

    if folder_paths:
        for path in folder_paths:
            obj = find_inventory_object(content, path)
            if obj is not None:
                entities.append((f"{_describe_object(obj)} (path '{_inventory_path_of(obj)}')", obj))
            else:
                WARN(
                    f"Locate folder '{path}'",
                    "not found in inventory; use full path like 'Datacenter/vm/Production' "
                    "or the exact folder / datacenter / cluster name",
                )
    elif vm_names:
        # Auto-infer parent folders from the VM list; dedupe.
        seen_folders: Dict[str, Tuple[object, List[str]]] = {}
        missing_vms: List[str] = []
        for name in vm_names:
            vm = find_vm(content, name)
            if vm is None:
                missing_vms.append(name)
                continue
            folder = _get_vm_parent_folder(vm)
            if folder is None:
                # VM with no proper folder (vApp-only, standalone) - fall back to VM itself
                entities.append((f"VM '{name}' (no parent folder; checking VM directly)", vm))
                continue
            key = _inventory_path_of(folder)
            if key not in seen_folders:
                seen_folders[key] = (folder, [name])
            else:
                seen_folders[key][1].append(name)
        for key, (folder, vms) in seen_folders.items():
            vm_hint = f"inferred from {len(vms)} VM(s): {', '.join(vms[:5])}"
            if len(vms) > 5:
                vm_hint += f", +{len(vms) - 5} more"
            entities.append((f"{_describe_object(folder)} (path '{key}', {vm_hint})", folder))
        for name in missing_vms:
            WARN(f"Locate VM '{name}'", "not found in inventory; skipping")

    if not entities:
        entities.append(("vCenter root folder", content.rootFolder))

    # Also check each VM individually when the operator asks for it.
    if per_vm_privs and vm_names:
        for name in vm_names:
            vm = find_vm(content, name)
            if vm is not None:
                entities.append((f"VM '{name}'", vm))

    # ---------- Run the actual privilege check ----------
    priv_ids = list(VMA_REQUIRED_PRIVILEGES.keys())
    # Map each entity label -> frozenset(missing_privilege_ids). Empty frozenset = all present.
    per_entity_missing: Dict[str, frozenset] = {}

    for label, ent in entities:
        try:
            result = auth_mgr.HasPrivilegeOnEntity(
                entity=ent, sessionId=session_key, privId=priv_ids,
            )
        except vim.fault.NoPermission:
            FAIL(
                f"Privilege check on {label}",
                "user has no permission to inspect authorization on this entity",
            )
            continue
        except Exception as e:  # noqa: BLE001
            FAIL(f"Privilege check on {label}", f"{type(e).__name__}: {e}")
            continue
        missing = frozenset(priv_ids[i] for i, has in enumerate(result) if not has)
        per_entity_missing[label] = missing

    # ---------- Group by identical missing-set so we print each gap once ----------
    groups: Dict[frozenset, List[str]] = {}
    for label, miss in per_entity_missing.items():
        groups.setdefault(miss, []).append(label)

    all_ok = True
    for miss, labels in groups.items():
        if not miss:
            # All required privs present for this group
            if len(labels) == 1:
                PASS(f"All {len(priv_ids)} required privileges present on {labels[0]}")
            else:
                PASS(f"All {len(priv_ids)} required privileges present on {len(labels)} entities",
                     ", ".join(labels[:3]) + (f", +{len(labels)-3} more" if len(labels) > 3 else ""))
        else:
            all_ok = False
            header = (f"{len(labels)} entity/entities missing {len(miss)} of {len(priv_ids)} privilege(s)"
                      if len(labels) > 1
                      else f"Missing privileges on {labels[0]}")
            FAIL(header, f"{len(miss)} of {len(priv_ids)} missing")
            if len(labels) > 1:
                for lbl in labels:
                    print(f"      • {lbl}")
            for pid in sorted(miss):
                print(f"      - {C.RED}{pid}{C.RST}  ({VMA_REQUIRED_PRIVILEGES[pid]})")
    return all_ok


def _discover_esxi_hosts(content, vm_names):
    hosts: set[str] = set()
    view = content.viewManager.CreateContainerView(
        content.rootFolder, [vim.VirtualMachine], True
    )
    try:
        vm_filter = set(vm_names) if vm_names else None
        for vm in view.view:
            if vm_filter is not None and vm.name not in vm_filter:
                continue
            try:
                h = vm.runtime.host
                if h and h.name:
                    hosts.add(h.name)
            except Exception:
                continue
    finally:
        view.Destroy()

    if hosts:
        if vm_names:
            PASS(f"Discovered ESXi hosts for {len(vm_names)} named VM(s)", ", ".join(sorted(hosts)))
        else:
            PASS("Discovered ESXi hosts across all VMs", f"{len(hosts)} host(s)")
    else:
        WARN("No ESXi hosts discovered", "check --vm names or vCenter inventory")
    return sorted(hosts)


def check_dns(names: Iterable[str]) -> None:
    head("D. DNS resolution")
    for name in names:
        try:
            socket.inet_pton(socket.AF_INET, name); PASS(f"Resolve {name}", "literal IPv4"); continue
        except (OSError, ValueError):
            pass
        try:
            socket.inet_pton(socket.AF_INET6, name); PASS(f"Resolve {name}", "literal IPv6"); continue
        except (OSError, ValueError):
            pass
        try:
            addrs = socket.getaddrinfo(name, None)
            ips = sorted({a[4][0] for a in addrs})
            PASS(f"Resolve {name}", ", ".join(ips))
        except socket.gaierror as e:
            FAIL(f"Resolve {name}", f"{e}")


def _tcp_ok(host, port, timeout):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, ""
    except socket.gaierror as e:
        return False, f"DNS: {e}"
    except socket.timeout:
        return False, f"timeout after {timeout}s"
    except ConnectionRefusedError:
        return False, "connection refused"
    except OSError as e:
        return False, f"{type(e).__name__}: {e}"


def check_ports(targets, timeout):
    head(f"E. TCP port reachability (timeout {timeout:g}s)")
    if not targets:
        SKIP("Port reachability", "no targets"); return
    max_workers = min(16, len(targets))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futs = {ex.submit(_tcp_ok, h, p, timeout): (h, p) for h, p in targets}
        for fut in as_completed(futs):
            h, p = futs[fut]
            ok, err = fut.result()
            label = f"TCP {h}:{p}"
            PASS(label) if ok else FAIL(label, err)


# ===========================================================================
# MODE 2 - ALL-VMS vSphere-side checks (F/G)
# ===========================================================================
def run_allvms_checks(host, port, user, password, insecure, vm_names, timeout):
    """vSphere-side pre-migration checks that apply to every VM regardless of OS."""

    head("F. vCenter version compatibility (virt-v2v)")
    si, err = connect_vcenter(host, port, user, password, insecure, timeout)
    if err:
        FAIL(f"Connect to {host}:{port}", err); return
    PASS(f"Connected to vCenter {host}:{port}")
    try:
        content = si.RetrieveContent()
        status, msg = vcenter_version_ok_for_v2v(content.about.apiVersion)
        _record(f"vCenter {content.about.apiVersion}", status, msg)

        head("G. Per-VM vSphere-side pre-migration checks")
        if not vm_names:
            WARN("No --vm names supplied", "run again with --vm NAME [--vm NAME ...] to enable per-VM checks")
            return
        for name in vm_names:
            vm = find_vm(content, name)
            if vm is None:
                FAIL(f"Locate VM '{name}'", "not found in vCenter inventory"); continue
            print(f"\n  {C.BLD}VM: {name} | Config: {vm.summary.config.numCpu} CPU, {vm.summary.config.memorySizeMB} MB, {vm.runtime.powerState} {C.RST}")

            _vm_check_guest_os(vm)
            _vm_check_tools(vm)
            _vm_check_snapshots(vm)
            _vm_check_boot(vm)
            _vm_check_vtpm(vm)
            _vm_check_datastore(vm)
            _vm_check_cdrom_and_disks(vm)
            _vm_check_network(vm, content)
    finally:
        try:
            Disconnect(si)
        except Exception:
            pass


def _vm_check_guest_os(vm) -> None:
    gid = getattr(vm.config, "guestId", "") or getattr(vm.summary.config, "guestId", "")
    gfull = getattr(vm.config, "guestFullName", "") or getattr(vm.summary.config, "guestFullName", "")
    label = f"[{vm.name}] Guest OS ({gid} | {gfull})"

    if not gid:
        WARN(label, "guestId not set on the VM")

    gid_lower = gid.lower()

    for bad in V2V_UNSUPPORTED_GUESTID_PREFIXES:
        if gid_lower.startswith(bad.lower()):
            FAIL(label, f" is on the virt-v2v unsupported list")
            return
    
    for good in V2V_SUPPORTED_GUESTID_PREFIXES:
        if gid_lower.startswith(good.lower()):
            PASS(label, f" is supported by virt-v2v")
            return

    WARN(label, f" is not listed: https://libguestfs.org/virt-v2v-support.1.html")

def _vm_check_vtpm(vm) -> None:
    label = f"[{vm.name}] vTPM"

    tpm_found = False
    if vm.config and vm.config.hardware:
        for device in vm.config.hardware.device:
            # Check if the device object is an instance of vim.vm.device.VirtualTPM
            if isinstance(device, vim.vm.device.VirtualTPM):
                tpm_found = True
                WARN(label, f"[TPM FOUND] VM '{vm.name}' has a vTPM device enabled.")
                break

    if not tpm_found:
        PASS(label, f"[NO TPM FOUND] in VM '{vm.name}'")

def _vm_check_tools(vm) -> None:
    g = vm.guest
    tools_status = getattr(g, "toolsStatus", None)
    tools_running = getattr(g, "toolsRunningStatus", None)
    tools_version = getattr(g, "toolsVersion", None) or "unknown"
    label = f"[{vm.name}] VMware Tools"

    if tools_status == "toolsOk" and tools_running == "guestToolsRunning":
        WARN(label, f"running, version {tools_version}")
    elif tools_status == "toolsOld":
        WARN(label, f"installed but out of date (version {tools_version})")
    elif tools_status == "toolsNotRunning":
        WARN(label, "installed but not running; some in-guest checks and warm migration features will be limited")
    elif tools_status == "toolsNotInstalled":
        PASS(label, "not installed")
    else:
        WARN(label, f"toolsStatus={tools_status}, toolsRunningStatus={tools_running}")


def _vm_check_snapshots(vm) -> None:
    label = f"[{vm.name}] Snapshots"

    try:
        if vm.snapshot is None:
            PASS(label, "no active snapshots"); return

        def _count(tree):
            n = 0
            for s in tree:
                n += 1 + _count(s.childSnapshotList)
            return n

        total = _count(vm.snapshot.rootSnapshotList)
        FAIL(label, f"{total} snapshot(s) present — consolidate or remove before migrating (virt-v2v requires a snapshot-free chain)")

    except Exception as e: 
        WARN(label, f"{type(e).__name__}: {e}")
        return None

def _vm_check_datastore(vm) -> None:
    label = f"[{vm.name}] Datastores"

    try:
        if len(vm.datastore)>1:
            WARN(label, str(len(vm.datastore)) + " datastore found")
        else:
            PASS(label, str(len(vm.datastore)) + " datastore found")

        for datastore in vm.datastore:
            print(f"      ℹ  {datastore.name} Free: {datastore.summary.freeSpace / 1024**3:.2f} GB Capacity: {datastore.summary.capacity / 1024**3:.2f} GB")

    except Exception as e:
        WARN(label, f"{type(e).__name__}: {e}")
        return None

def _vm_check_boot(vm) -> None:
    cfg = vm.config
    firmware = getattr(cfg, "firmware", "bios") or "bios"
    boot = getattr(cfg, "bootOptions", None)

    # Secure Boot
    label = f"[{vm.name}] Secure Boot"
    if firmware != "efi":
        PASS(label, f"firmware={firmware} (Secure Boot not applicable)")
    else:
        sb = bool(getattr(boot, "efiSecureBootEnabled", False)) if boot else False
        if sb:
            FAIL(label, (
                "EFI Secure Boot is ENABLED. Either disable it in vSphere (Edit Settings > "
                "VM Options > Boot Options > Secure Boot) before migrating, or tell the "
                "migration team to set smm.enabled=true on the target KubeVirt VM — "
                "otherwise the new VM is rejected at creation."
            ))
        else:
            PASS(label, "EFI firmware, Secure Boot disabled")

    # PXE / network boot
    label = f"[{vm.name}] Boot order"
    if boot and getattr(boot, "bootOrder", None):
        pxe_first = any(
            isinstance(d, vim.vm.BootOptions.BootableEthernetDevice)
            for d in boot.bootOrder[:1]
        )
        pxe_present = any(
            isinstance(d, vim.vm.BootOptions.BootableEthernetDevice)
            for d in boot.bootOrder
        )
        if pxe_first:
            FAIL(label, "PXE / network device is FIRST in boot order — the migrated VM will attempt PXE and hang")
        elif pxe_present:
            WARN(label, "PXE / network device present in boot order but not first — usually fine, verify target boot menu")
        else:
            PASS(label, "no PXE / network device in boot order")
    else:
        PASS(label, "no explicit boot order set (firmware default)")


def _vm_check_cdrom_and_disks(vm) -> None:
    cdroms_mounted: List[str] = []
    ide_disks: List[str] = []
    rdm_disks: List[str] = []
    scsi_disks: List[str] = []
    controllers = {}

    for dev in vm.config.hardware.device:
        if isinstance(dev, (vim.vm.device.VirtualIDEController, vim.vm.device.VirtualSCSIController,
                            vim.vm.device.ParaVirtualSCSIController, vim.vm.device.VirtualLsiLogicController,
                            vim.vm.device.VirtualLsiLogicSASController, vim.vm.device.VirtualBusLogicController)):
            controllers[dev.key] = dev

    for dev in vm.config.hardware.device:
        if isinstance(dev, vim.vm.device.VirtualCdrom):
            backing = dev.backing
            conn = getattr(dev, "connectable", None)
            connected = bool(conn and conn.connected)
            start_conn = bool(conn and conn.startConnected)
            iso_mounted = isinstance(backing, vim.vm.device.VirtualCdrom.IsoBackingInfo)
            host_dev = isinstance(backing, vim.vm.device.VirtualCdrom.AtapiBackingInfo)
            if iso_mounted and (connected or start_conn):
                cdroms_mounted.append(f"ISO backing '{getattr(backing, 'fileName', '?')}'")
            elif host_dev and (connected or start_conn):
                cdroms_mounted.append("host device passthrough (ATAPI)")
        elif isinstance(dev, vim.vm.device.VirtualDisk):
            ctrl = controllers.get(dev.controllerKey)
            ctrl_type = type(ctrl).__name__ if ctrl else "unknown"
            backing = dev.backing
            if isinstance(backing, vim.vm.device.VirtualDisk.RawDiskMappingVer1BackingInfo):
                rdm_disks.append(f"{dev.deviceInfo.label} ({ctrl_type})")
            elif "IDE" in ctrl_type:
                ide_disks.append(f"{dev.deviceInfo.label}")
            else:
                scsi_disks.append(f"{dev.deviceInfo.label}")

    label = f"[{vm.name}] CD-ROM / removable media"
    if cdroms_mounted:
        FAIL(label, "; ".join(cdroms_mounted) + " — disconnect before migrating")
    else:
        PASS(label, "no ISO or host CD-ROM attached")

    label = f"[{vm.name}] Disks"
    if rdm_disks:
        FAIL(label, f"Raw Device Mapping (RDM) disks not supported by virt-v2v: {', '.join(rdm_disks)}")
    elif ide_disks:
        WARN(label, f"IDE-attached disks detected: {', '.join(ide_disks)} — SCSI/paravirtual is preferred")
    else:
        disk_count = len(scsi_disks)
        if disk_count == 0:
            FAIL(label, "no virtual disks present")
        else:
            PASS(label, f"{disk_count} SCSI/paravirtual disk(s)")


def _vm_check_network(vm, content) -> None:
    nics = [d for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualEthernetCard)]
    label = f"[{vm.name}] NICs"
    if not nics:
        WARN(label, "no virtual NICs present"); return

    problems: List[str] = []
    infos: List[str] = []
    for nic in nics:
        nic_type = type(nic).__name__.replace("Virtual", "")
        addr_type = getattr(nic, "addressType", "?")
        backing = nic.backing
        pg_name = "?"
        vlan_info = ""

        if isinstance(backing, vim.vm.device.VirtualEthernetCard.NetworkBackingInfo):
            pg_name = getattr(backing, "deviceName", "?")
            vlan_info = "std vSwitch port group"
        elif isinstance(backing, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
            try:
                dvpg_ref = backing.port.portgroupKey
                dvs_uuid = backing.port.switchUuid
                # Look up the port group to read VLAN + MAC learning
                for dvs in content.viewManager.CreateContainerView(
                    content.rootFolder, [vim.dvs.VmwareDistributedVirtualSwitch], True
                ).view:
                    if dvs.uuid == dvs_uuid:
                        for pg in dvs.portgroup:
                            if pg.key == dvpg_ref:
                                pg_name = pg.name
                                vlan = getattr(pg.config.defaultPortConfig, "vlan", None)
                                if isinstance(vlan, vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec):
                                    vlan_info = f"DVS VLAN {vlan.vlanId}"
                                elif isinstance(vlan, vim.dvs.VmwareDistributedVirtualSwitch.TrunkVlanSpec):
                                    ranges = ",".join(f"{r.start}-{r.end}" for r in vlan.vlanId)
                                    vlan_info = f"DVS VLAN trunk {ranges}"
                                    problems.append(f"NIC on trunk port group '{pg_name}' — KubeVirt NAD must be configured to match")
                                elif isinstance(vlan, vim.dvs.VmwareDistributedVirtualSwitch.PvlanSpec):
                                    vlan_info = f"DVS PVLAN {vlan.pvlanId}"
                                    problems.append(f"NIC on PVLAN '{pg_name}' — PVLAN is not portable to KubeVirt as-is")
                                # MAC learning (for nested / multi-MAC guests)
                                mac_mgmt = getattr(pg.config.defaultPortConfig, "macManagementPolicy", None)
                                if mac_mgmt and getattr(mac_mgmt, "macLearningPolicy", None):
                                    if mac_mgmt.macLearningPolicy.enabled:
                                        vlan_info += ", MAC learning enabled"
                                break
                        break
            except Exception as e:  # noqa: BLE001
                vlan_info = f"DVS lookup failed: {type(e).__name__}"

        infos.append(f"{nic_type} @ '{pg_name}' ({vlan_info}, addr={addr_type})")

    if problems:
        FAIL(label, "; ".join(problems))
        for i in infos:
            print(f"      ℹ  {i}")
    else:
        PASS(label, f"{len(nics)} NIC(s)")
        for i in infos:
            print(f"      ℹ  {i}")


# ===========================================================================
# MODE 3 - WINDOWS pre-migration checks + prep (H)
# ===========================================================================
def run_windows_checks(
    host, port, user, password, insecure, vm_names, timeout,
    win_user, win_password, win_auth, win_transport, win_port, apply_changes,
):

    head("H. Windows VM pre-migration checks + prep")
    if not vm_names:
        SKIP("Windows checks", "no --vm names supplied"); return
    try:
        import winrm  # noqa: F401
    except ImportError:
        FAIL(
            "pywinrm not installed (jump host)",
            "pywinrm is needed on THIS host (where you're running vma-preflight.py), "
            "not on the Windows VM. Install with:\n"
            "      pip install pywinrm            # NTLM/basic auth\n"
            "      pip install 'pywinrm[kerberos]'  # if you want Kerberos\n"
            "    Then re-run the same command."
        )
        return
    if not win_user:
        FAIL("Windows guest access", "no --win-user supplied")
        return
    if not win_password:
        win_password = os.environ.get("WIN_PASSWORD")
    if not win_password:
        try:
            win_password = getpass.getpass(f"Windows password for {win_user}: ")
        except (EOFError, KeyboardInterrupt):
            FAIL("Windows password prompt", "no password provided"); return

    si, err = connect_vcenter(host, port, user, password, insecure, timeout)
    if err:
        FAIL(f"Connect to vCenter {host}:{port}", err); return
    PASS(f"Connected to vCenter {host}:{port}")

    if apply_changes:
        print(f"  {C.MAG}[APPLY MODE]{C.RST} changes to the guest WILL be executed")
    else:
        print(f"  {C.CYN}[DRY-RUN]{C.RST} changes are shown as [PLAN] and NOT executed; re-run with --apply to make them")

    try:
        content = si.RetrieveContent()
        for name in vm_names:
            vm = find_vm(content, name)
            if vm is None:
                FAIL(f"Locate VM '{name}'", "not found in vCenter inventory"); continue

            # Skip non-Windows guests cleanly - no point probing WinRM on Linux.
            is_win, guest_label = _guest_is_windows(vm)
            if not is_win:
                SKIP(f"[{name}] Windows checks", f"guest is not Windows ({guest_label})")
                continue

            print(f"\n  {C.BLD}Windows VM: {name}{C.RST}  (detected: {guest_label})")

            # Resolve a reachable address for WinRM.
            addr = _pick_guest_address(vm)
            if not addr:
                FAIL(f"[{name}] Guest IP",
                     "no IP available from VMware Tools; skipping in-guest checks. "
                     "Ensure VMware Tools is running before migration.")
                continue
            PASS(f"[{name}] Guest IP", addr)

            # Probe the WinRM port BEFORE trying to open a session.
            # If it's closed we can give a much better error than pywinrm would.
            if not _winrm_port_reachable(addr, win_port, name, timeout):
                continue

            session = _winrm_session(addr, win_port, win_user, win_password, win_auth, win_transport)
            if session is None:
                FAIL(f"[{name}] WinRM session", f"could not build session to {addr}:{win_port}")
                continue

            # Cheap auth probe so we surface bad creds / disabled auth mechanism
            # up front instead of failing on the first real check.
            if not _winrm_auth_ok(session, name):
                continue

            # 1. Basic vs Dynamic disks
            _win_check_basic_disk(session, name)
            # 2. Secure Boot state (guest view)
            _win_check_secure_boot(session, name, vm)
            # 3. Hibernation off (can change)
            _win_check_or_disable_hibernation(session, name, apply_changes)
            # 4. Fast Startup off (can change with --apply)
            _win_check_fast_startup(session, name, apply_changes)
            # 5. Guest shutdown (can change)
            _win_shutdown_guest(session, name, apply_changes)
            # 6. Confirm Powered Off in vSphere (after step 5 gave the guest time to shut down)
            _vsphere_confirm_powered_off(vm, name, apply_changes)
    finally:
        try:
            Disconnect(si)
        except Exception:
            pass


def _guest_is_windows(vm) -> Tuple[bool, str]:
    """Return (is_windows, short_label) for a VM.

    Prefers VMware Tools' guestFamily when available; falls back to the
    configured guestId. Returns a human-readable label for the summary line.
    """
    g = getattr(vm, "guest", None)
    fam = (getattr(g, "guestFamily", "") or "").lower() if g else ""
    gid = (getattr(vm.config, "guestId", "") or "")
    gfull = (getattr(vm.config, "guestFullName", "") or getattr(g, "guestFullName", "")) if g else gid

    if fam == "windowsguest":
        return True, f"guestFamily=windowsGuest, '{gfull or gid}'"
    if fam in ("linuxguest", "othernixosguestfamily", "darwinguestfamily",
               "netwareguest", "solarisguest", "othernonlinuxguest"):
        return False, f"guestFamily={fam}, '{gfull or gid}'"

    # Tools may not be running - fall back to configured guestId.
    low = gid.lower()
    if "windows" in low or low.startswith("win"):
        return True, f"guestId={gid or 'unknown'}"
    if gid:
        return False, f"guestId={gid}"
    return False, "guest OS unknown (Tools not running and no guestId)"


def _pick_guest_address(vm) -> Optional[str]:
    g = vm.guest
    if g and getattr(g, "ipAddress", None):
        return g.ipAddress
    # Fallback: first non-link-local IPv4 from any NIC
    for nic in getattr(g, "net", []) or []:
        for ip in getattr(nic, "ipAddress", []) or []:
            if not ip.startswith(("169.254.", "fe80:")):
                return ip
    return None


def _winrm_port_reachable(host: str, port: int, vm_name: str, timeout: float) -> bool:
    """Confirm the guest is listening on the WinRM port before we try to auth.

    A clean FAIL with concrete remediation is much more useful than pywinrm's
    error, which tends to be a wall of urllib3 traceback."""
    label = f"[{vm_name}] WinRM port TCP {host}:{port}"
    ok, err = _tcp_ok(host, port, timeout)
    if ok:
        PASS(label, "listener reachable")
        return True

    # Craft a targeted hint based on the port we tried.
    if port in (5985, 5986):
        hint = (
            f"could not open TCP {host}:{port}: {err}. "
            f"On the target Windows VM, run (elevated PowerShell):\n"
            f"      Set-NetConnectionProfile -NetworkCategory Private  # if on Public net\n"
            f"      winrm quickconfig -force\n"
            f"      Get-Service WinRM        # confirm 'Running'\n"
            f"      Enable-PSRemoting -Force # if quickconfig complained\n"
            f"    Also verify a firewall rule allows inbound {port}/TCP from this jump host."
        )
    else:
        hint = f"could not open TCP {host}:{port}: {err}. Check the listener and firewall."
    FAIL(label, hint)
    return False


def _winrm_session(host, port, user, password, auth, transport):
    import winrm
    scheme = "https" if transport == "https" else "http"
    endpoint = f"{scheme}://{host}:{port}/wsman"
    try:
        s = winrm.Session(
            endpoint,
            auth=(user, password),
            transport=auth,       # 'ntlm', 'basic', 'kerberos', 'credssp'
            server_cert_validation="ignore" if scheme == "https" else "validate",
        )
        return s
    except Exception as e:  # noqa: BLE001
        FAIL("Build WinRM session", f"{type(e).__name__}: {e}")
        return None


def _winrm_auth_ok(session, vm_name: str) -> bool:
    """Run a trivial command to prove auth actually works. Catches:
      - 401 Unauthorized (bad password, or NTLM disabled on the guest)
      - 403 (auth mechanism not enabled)
      - connection reset (SSL cert mismatch on https transport)
    """
    label = f"[{vm_name}] WinRM auth"
    try:
        rc, out, err = _run_ps(session, r"$env:COMPUTERNAME")
    except Exception as e:  # noqa: BLE001
        msg = str(e)
        hint = ""
        if "401" in msg or "Unauthorized" in msg:
            hint = (
                " — bad password, or the guest doesn't accept this --win-auth. "
                "On the VM: winrm get winrm/config/service/auth   (check Basic/NTLM/Negotiate values). "
                "For a workgroup guest via NTLM: use user 'HOSTNAME\\\\Administrator' or '.\\\\Administrator'."
            )
        elif "certificate" in msg.lower() or "ssl" in msg.lower():
            hint = " — TLS trust issue; try --win-transport http (5985) or a proper cert on the guest."
        FAIL(label, f"{type(e).__name__}: {msg}{hint}")
        return False
    if rc != 0:
        FAIL(label, f"probe command returned rc={rc}: {err.strip() or out.strip()}")
        return False
    PASS(label, f"authenticated as {out.strip() or '(no output)'}")
    return True


def _run_ps(session, script: str) -> Tuple[int, str, str]:
    r = session.run_ps(script)
    return r.status_code, r.std_out.decode(errors="replace"), r.std_err.decode(errors="replace")


def _win_check_basic_disk(session, vm_name):
    label = f"[{vm_name}] Disk provisioning (Basic vs Dynamic)"
    rc, out, err = _run_ps(
        session,
        r'Get-Disk | Select-Object Number, FriendlyName, PartitionStyle, ProvisioningType | '
        r'ForEach-Object { "$($_.Number)`t$($_.FriendlyName)`t$($_.PartitionStyle)`t$($_.ProvisioningType)" }'
    )
    if rc != 0:
        FAIL(label, f"Get-Disk failed rc={rc}: {err.strip() or out.strip()}"); return

    lines = [l for l in out.splitlines() if l.strip()]
    dynamic: List[str] = []
    parsed: List[str] = []
    for line in lines:
        cols = line.split("\t")
        if len(cols) < 4:
            continue
        num, fname, style, prov = cols[0], cols[1], cols[2], cols[3]
        parsed.append(f"#{num} {fname} style={style} prov={prov}")
        # In PowerShell Get-Disk output, dynamic disks show PartitionStyle=MBR/GPT
        # and ProvisioningType may not distinguish; the definitive check is via
        # Get-Disk's IsBoot / OperationalStatus and via diskpart. Simplest: use
        # "PartitionStyle" == "Dynamic" (older) OR check with Get-Volume.
        if style.strip().lower() == "raw":
            continue
        if "dynamic" in prov.strip().lower() or "dynamic" in style.strip().lower():
            dynamic.append(f"#{num} {fname}")

    for p in parsed:
        print(f"      • {p}")

    if dynamic:
        FAIL(label, f"Dynamic disk(s): {', '.join(dynamic)} — convert to Basic before migration")
    else:
        PASS(label, f"{len(parsed)} disk(s), all Basic")


def _win_check_secure_boot(session, vm_name, vm):
    label = f"[{vm_name}] Secure Boot (guest view)"
    rc, out, err = _run_ps(session, r'try { (Confirm-SecureBootUEFI).ToString() } catch { "NA" }')
    val = out.strip().splitlines()[-1] if out.strip() else ""
    firmware = getattr(vm.config, "firmware", "bios") or "bios"
    vsphere_sb = bool(getattr(vm.config.bootOptions, "efiSecureBootEnabled", False)) if vm.config.bootOptions else False

    if val == "True":
        FAIL(label, (
            f"Guest reports Secure Boot ENABLED. vSphere: firmware={firmware}, "
            f"efiSecureBootEnabled={vsphere_sb}. Either disable Secure Boot in vSphere "
            f"before migrating, or set smm.enabled=true on the target KubeVirt VM."
        ))
    elif val == "False":
        PASS(label, f"guest reports Secure Boot disabled (vSphere firmware={firmware})")
    elif val == "NA":
        PASS(label, f"cmdlet not supported — guest is BIOS, not UEFI (vSphere firmware={firmware})")
    else:
        WARN(label, f"unexpected output: rc={rc} out={out!r} err={err!r}")


def _win_check_or_disable_hibernation(session, vm_name, apply_changes):
    label = f"[{vm_name}] Hibernation"
    rc, out, _ = _run_ps(
        session,
        r'(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Power" -Name HibernateEnabled '
        r'-ErrorAction SilentlyContinue).HibernateEnabled'
    )
    val = out.strip()
    is_on = val in ("1", "1L")
    if not is_on:
        PASS(label, "already disabled (HibernateEnabled != 1)")
    else:
        if not apply_changes:
            PLAN(label, "hibernation is ON — [DRY-RUN] would run: powercfg /h off (also disables Fast Startup)")
        else:
            rc2, out2, err2 = _run_ps(session, r"powercfg /h off")
            if rc2 == 0:
                DONE(label, "ran: powercfg /h off (hibernation + Fast Startup disabled)")
            else:
                FAIL(label, f"powercfg /h off failed rc={rc2}: {err2.strip() or out2.strip()}")


def _win_check_fast_startup(session, vm_name, apply_changes):
    label = f"[{vm_name}] Fast Startup"
    reg_path = r"HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power"
    rc, out, _ = _run_ps(
        session,
        rf'(Get-ItemProperty "{reg_path}" '
        r'-Name HiberbootEnabled -ErrorAction SilentlyContinue).HiberbootEnabled'
    )
    val = out.strip()
    if val in ("", "0"):
        PASS(label, "off (HiberbootEnabled=0 or unset)")
        return
    if val != "1":
        WARN(label, f"unexpected value: {val!r}")
        return

    # HiberbootEnabled == 1 : Fast Startup is on.
    if not apply_changes:
        PLAN(label, "HiberbootEnabled=1 — [DRY-RUN] would set it to 0 via "
                    r'Set-ItemProperty "HKLM:\...\Session Manager\Power" -Name HiberbootEnabled -Value 0')
        return

    rc2, out2, err2 = _run_ps(
        session,
        rf'Set-ItemProperty -Path "{reg_path}" -Name HiberbootEnabled -Value 0 -Type DWord; '
        rf'(Get-ItemProperty "{reg_path}" -Name HiberbootEnabled).HiberbootEnabled'
    )
    verify = (out2.strip().splitlines() or [""])[-1]
    if rc2 == 0 and verify == "0":
        DONE(label, "HiberbootEnabled set to 0 (Fast Startup disabled)")
    else:
        FAIL(label, f"failed to set HiberbootEnabled=0: rc={rc2} "
                    f"stdout={out2.strip()!r} stderr={err2.strip()!r}")


def _win_shutdown_guest(session, vm_name, apply_changes):
    label = f"[{vm_name}] Guest shutdown"
    if not apply_changes:
        PLAN(label, "[DRY-RUN] would run inside guest: shutdown /s /t 0  (clean OS shutdown — not Suspend / not Restart)")
        return
    rc, out, err = _run_ps(session, r'shutdown /s /t 0')
    if rc == 0:
        DONE(label, "shutdown /s /t 0 issued; waiting up to 120s for vSphere to see Powered Off")
    else:
        FAIL(label, f"shutdown failed rc={rc}: {err.strip() or out.strip()}")


def _vsphere_confirm_powered_off(vm, vm_name, apply_changes):
    label = f"[{vm_name}] vSphere power state"
    if not apply_changes:
        state = getattr(vm.runtime, "powerState", "?")
        if str(state) == "poweredOff":
            PASS(label, "already Powered Off")
        elif str(state) == "suspended":
            FAIL(label, "Suspended — same unclean filesystem as running; power on, shut down cleanly, then re-check")
        else:
            PLAN(label, f"current state = {state}; after --apply the shutdown, expected: poweredOff")
        return
    # Apply mode: poll for up to 120s
    for _ in range(24):
        try:
            state = str(getattr(vm.runtime, "powerState", "?"))
        except Exception:
            state = "?"
        if state == "poweredOff":
            PASS(label, "confirmed Powered Off"); return
        if state == "suspended":
            FAIL(label, "Suspended (not Powered Off) — investigate"); return
        time.sleep(5)
    WARN(label, "did not reach Powered Off within 120s; re-check manually")


# ===========================================================================
# Summary
# ===========================================================================
def summary() -> int:
    counts = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0, "PLAN": 0, "DONE": 0}
    for _, _, s, _ in RESULTS:
        counts[s] += 1
    print(f"\n{C.BLD}== Summary =={C.RST}")
    print(
        f"  {C.GRN}PASS: {counts['PASS']}{C.RST}   "
        f"{C.RED}FAIL: {counts['FAIL']}{C.RST}   "
        f"{C.YLW}WARN: {counts['WARN']}{C.RST}   "
        f"{C.CYN}SKIP: {counts['SKIP']}{C.RST}   "
        f"{C.MAG}PLAN: {counts['PLAN']}{C.RST}   "
        f"{C.GRN}DONE: {counts['DONE']}{C.RST}"
    )
    fails = [(sec, n, d) for sec, n, s, d in RESULTS if s == "FAIL"]
    if fails:
        print(f"\n{C.RED}Failures:{C.RST}")
        for sec, n, d in fails:
            suffix = f"  — {d}" if d else ""
            print(f"  - [{sec}] {n}{suffix}")
        print(f"\n{C.RED}Environment is NOT ready for VMA.{C.RST}")
        return 1
    warns = counts["WARN"]
    plans = counts["PLAN"]
    if plans:
        print(f"\n{C.MAG}{plans} pending change(s) shown as [PLAN]. Re-run with --apply to execute them.{C.RST}")
    if warns:
        print(f"{C.YLW}{warns} warning(s) — review before starting migration.{C.RST}")
    if not fails:
        print(f"\n{C.GRN}All checks passed.{C.RST}")
    return 0


# ===========================================================================
# Interactive menu
# ===========================================================================
# Per-mode metadata: title, one-liner, required flags, optional flags, example.
MODE_INFO: Dict[str, Dict[str, Any]] = {
    "preflight": {
        "title": "vCenter environment preflight only",
        "summary": "auth, VMA-required privileges, ESXi discovery, DNS, TCP 443/902",
        "required": ["--vcenter", "--user", "(--password | VC_PASSWORD | prompt)"],
        "optional": ["--vm NAME | --vm-file PATH", "--folder PATH  (repeatable)",
                     "--per-vm-privs  (also check each VM individually)",
                     "--esxi HOST", "--insecure",
                     "--skip-dns", "--skip-ports", "--timeout N"],
        "example": (
            "python vma-preflight.py --run preflight \\\n"
            "    --vcenter vcenter.corp.example.com \\\n"
            "    --user    svc-vma@vsphere.local \\\n"
            "    --folder  'MyDC/vm/Production' \\\n"
            "    --insecure"
        ),
    },
    "allvms": {
        "title": "All-VMs vSphere-side checks only",
        "summary": "vCenter version, guest OS v2v support, Tools, snapshots, Secure Boot, "
                   "PXE boot, CD-ROM, disks (RDM/IDE), NIC port group + VLAN",
        "required": ["--vcenter", "--user", "(--password | VC_PASSWORD | prompt)",
                     "--vm NAME  (or --vm-file PATH)"],
        "optional": ["--insecure", "--timeout N"],
        "example": (
            "python vma-preflight.py --run allvms \\\n"
            "    --vcenter vcenter.corp.example.com \\\n"
            "    --user    svc-vma@vsphere.local \\\n"
            "    --vm-file wave1.txt \\\n"
            "    --insecure"
        ),
    },
    "windows": {
        "title": "Windows VM pre-migration checks (via WinRM)",
        "summary": "Basic disks, Secure Boot, hibernation, Fast Startup, clean shutdown, "
                   "vSphere power-state verify. Changes dry-run unless --apply.",
        "required": ["--vcenter", "--user", "(--password | VC_PASSWORD | prompt)",
                     "--vm NAME  (or --vm-file PATH)",
                     "--win-user USER", "(--win-password | WIN_PASSWORD | prompt)"],
        "optional": ["--apply", "--win-auth {ntlm,basic,kerberos,credssp}",
                     "--win-transport {http,https}", "--win-port N",
                     "--insecure", "--timeout N"],
        "example": (
            "python vma-preflight.py --run windows --apply \\\n"
            "    --vcenter vcenter.corp.example.com \\\n"
            "    --user    svc-vma@vsphere.local \\\n"
            "    --vm      win-file-01 \\\n"
            "    --win-user Administrator \\\n"
            "    --insecure"
        ),
    },
    "all": {
        "title": "All of the above (preflight + allvms + windows)",
        "summary": "everything, end to end",
        "required": ["--vcenter", "--user", "(--password | VC_PASSWORD | prompt)",
                     "--vm NAME  (or --vm-file PATH)",
                     "--win-user USER  (for the Windows VMs in the list)",
                     "(--win-password | WIN_PASSWORD | prompt)"],
        "optional": ["--apply", "--insecure", "--esxi HOST", "--skip-dns", "--skip-ports",
                     "--win-auth {ntlm,basic,kerberos,credssp}",
                     "--win-transport {http,https}", "--win-port N",
                     "--timeout N"],
        "example": (
            "python vma-preflight.py --run all --apply \\\n"
            "    --vcenter vcenter.corp.example.com \\\n"
            "    --user    svc-vma@vsphere.local \\\n"
            "    --vm-file wave1.txt \\\n"
            "    --win-user Administrator \\\n"
            "    --insecure"
        ),
    },
}


def _render_mode_help(mode: str, indent: str = "     ") -> str:
    info = MODE_INFO[mode]
    lines = [
        f"{indent}{C.CYN}Does:{C.RST}     {info['summary']}",
        f"{indent}{C.CYN}Required:{C.RST} {', '.join(info['required'])}",
        f"{indent}{C.CYN}Optional:{C.RST} {', '.join(info['optional'])}",
        f"{indent}{C.CYN}Example:{C.RST}",
    ]
    for ex_line in info["example"].splitlines():
        lines.append(f"{indent}  {ex_line}")
    return "\n".join(lines)


def print_menu() -> None:
    print(f"\n{C.BLD}Palette VMO / VMA Pre-flight - what do you want to run?{C.RST}\n")
    for num, key in ((1, "preflight"), (2, "allvms"), (3, "windows"), (4, "all")):
        title = MODE_INFO[key]["title"]
        print(f"  {C.BLD}{num}){C.RST} {title}")
        print(_render_mode_help(key))
        print()
    print(f"  {C.BLD}q){C.RST} Quit")
    print()


def prompt_menu() -> Optional[str]:
    print_menu()
    while True:
        try:
            choice = input("Choice [1-4, q]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return None
        if choice in ("1", "preflight"): return "preflight"
        if choice in ("2", "allvms"):    return "allvms"
        if choice in ("3", "windows"):   return "windows"
        if choice in ("4", "all"):       return "all"
        if choice in ("q", "quit", "exit"): return None
        print("  Enter 1, 2, 3, 4, or q.")


def print_mode_example_hint(mode: str) -> None:
    """Print a copy-pasteable example for a mode after a startup FAIL."""
    if mode not in MODE_INFO:
        return
    info = MODE_INFO[mode]
    print(f"\n{C.CYN}Required for '{mode}':{C.RST} {', '.join(info['required'])}")
    print(f"{C.CYN}Example:{C.RST}")
    for line in info["example"].splitlines():
        print(f"  {line}")


# ---------------------------------------------------------------------------
# Interactive prompts (used only when the menu was navigated, not with --run)
# ---------------------------------------------------------------------------
def _prompt_str(msg: str, default: Optional[str] = None) -> Optional[str]:
    label = f"{msg} [{default}]: " if default else f"{msg}: "
    try:
        v = input(label).strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    return v or default


def _prompt_secret(msg: str) -> Optional[str]:
    try:
        return getpass.getpass(f"{msg}: ")
    except (EOFError, KeyboardInterrupt):
        print()
        return None


def _prompt_yn(msg: str, default: bool = False) -> Optional[bool]:
    d = "Y/n" if default else "y/N"
    try:
        v = input(f"{msg} [{d}]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return None
    if not v:
        return default
    return v in ("y", "yes", "true", "1")


def interactive_fill(mode: str, args) -> bool:
    """Fill missing args by prompting the user. Returns False if cancelled."""
    print(f"\n{C.BLD}Interactive setup for '{mode}'{C.RST}  (press Ctrl-C or blank at any prompt to cancel)")

    # ---- vCenter ----
    if not args.vcenter:
        v = _prompt_str("vCenter host (or host:port, or https://host/sdk)")
        if not v: return False
        args.vcenter = v

    if not args.user:
        v = _prompt_str("vCenter username", default="administrator@vsphere.local")
        if not v: return False
        args.user = v

    if not args.password and not os.environ.get("VC_PASSWORD"):
        v = _prompt_secret(f"vCenter password for {args.user}")
        if v is None: return False
        args.password = v

    if not args.insecure:
        v = _prompt_yn("Skip TLS certificate verification (self-signed vCenter)?", default=True)
        if v is None: return False
        args.insecure = v

    # ---- VM list (allvms / windows / all) ----
    if mode in ("allvms", "windows", "all") and not args.vm and not args.vm_file:
        print("  Enter one of:")
        print("    - comma-separated VM names:    web-01,db-01")
        print("    - path to a VM list file:      /home/me/vms.txt   (or @/home/me/vms.txt)")
        v = _prompt_str("VMs to check")
        if not v: return False
        # Strip surrounding quotes users often paste in from a shell.
        v = v.strip().strip("'\"").strip()
        # Explicit @ prefix always means "file".
        if v.startswith("@"):
            args.vm_file = v[1:].strip().strip("'\"")
        # Otherwise, if it looks like a path and the file exists, treat as file.
        elif os.path.isfile(v):
            args.vm_file = v
        # Path-shape heuristic (slashes, no commas): assume file even if it
        # doesn't exist yet, so the user gets a clear "cannot read" error
        # instead of a confusing "VM not found in inventory".
        elif ("/" in v or "\\" in v) and "," not in v:
            args.vm_file = v
        else:
            args.vm = [x.strip() for x in v.split(",") if x.strip()]

    # ---- Privilege scope for preflight (optional folder / cluster / datacenter) ----
    if mode in ("preflight", "all") and not args.folder:
        print("  Where should VMA privileges be checked? "
              "(role assignments usually live at a folder / cluster / datacenter)")
        print("  Leave blank to check on the vCenter root folder (or the --vm entities if given).")
        v = _prompt_str(
            "vSphere inventory path(s), comma-separated (e.g. 'MyDC/vm/Production')",
            default="",
        )
        if v:
            args.folder = [x.strip() for x in v.split(",") if x.strip()]

    # ---- Windows guest args (windows / all) ----
    if mode in ("windows", "all"):
        if not args.win_user:
            v = _prompt_str("Windows guest username", default="Administrator")
            if not v:
                if mode == "windows": return False
            else:
                args.win_user = v
        if args.win_user and not args.win_password and not os.environ.get("WIN_PASSWORD"):
            v = _prompt_secret(f"Windows password for {args.win_user}")
            if v is None: return False
            args.win_password = v
        if not args.apply:
            v = _prompt_yn(
                "Apply Windows changes now?  (No = dry-run; changes shown as [PLAN])",
                default=False,
            )
            if v is None: return False
            args.apply = v

    return True


# ---------------------------------------------------------------------------
# --vm / --vm-file merge (used by both CLI and interactive paths)
# ---------------------------------------------------------------------------
def resolve_vm_list(args) -> Optional[str]:
    """Merge args.vm + args.vm_file into args.vm (deduped, order-preserving).
    Returns an error string or None."""
    vm_from_cli = list(args.vm or [])
    vm_list: List[str] = list(dict.fromkeys(vm_from_cli))
    if args.vm_file:
        file_vms, err = load_vm_file(args.vm_file)
        if err:
            return err
        added = 0
        for name in file_vms:
            if name not in vm_list:
                vm_list.append(name); added += 1
        print(f"  VM list: {len(vm_list)} unique VM(s) "
              f"({len(vm_from_cli)} from --vm, {added} added from {args.vm_file})")
    args.vm = vm_list
    return None


# ===========================================================================
# CLI
# ===========================================================================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vma-preflight",
        description=(
            "Palette VMO / VMA environment pre-flight and per-VM pre-migration checker."
        ),
    )
    p.add_argument(
        "--run",
        choices=("preflight", "allvms", "windows", "all"),
        help="Which set of checks to run. If omitted, an interactive menu is shown.",
    )

    # vCenter args
    p.add_argument("--vcenter", help="vCenter endpoint: host, host:port, or https://host/sdk")
    p.add_argument("--user", help="vCenter username (e.g. svc-vma@vsphere.local)")
    p.add_argument("--password", help="vCenter password. Prefers env VC_PASSWORD; prompts if neither.")
    p.add_argument("--insecure", action="store_true", help="Skip TLS verification for vCenter.")
    p.add_argument("--vm", action="append", default=[], metavar="NAME", help="VM name (repeatable).")
    p.add_argument(
        "--vm-file",
        metavar="PATH",
        help=(
            "Text file with one VM name per line. Blank lines and lines starting with '#' "
            "are ignored. Names from --vm-file merge with any --vm flags (order preserved, "
            "duplicates removed)."
        ),
    )
    p.add_argument(
        "--folder",
        action="append",
        default=[],
        metavar="PATH",
        help=(
            "vSphere inventory path (or bare folder / datacenter / cluster name) to check "
            "VMA privileges on. Repeatable. Example: 'MyDC/vm/Production'. If given, "
            "privileges are checked here instead of inferring from --vm parents."
        ),
    )
    p.add_argument(
        "--per-vm-privs",
        action="store_true",
        help=(
            "ALSO check VMA privileges on each --vm individually, on top of the folder-scope "
            "check. Useful for diagnosing broken role propagation on specific VMs. "
            "Default off (folder-scope only, since role grants almost always live at a folder)."
        ),
    )
    p.add_argument("--esxi", action="append", default=[], metavar="HOST", help="Extra ESXi host for DNS + 902 checks.")
    p.add_argument("--skip-dns", action="store_true", help="Skip DNS checks in preflight.")
    p.add_argument("--skip-ports", action="store_true", help="Skip TCP port checks in preflight.")
    p.add_argument("--timeout", type=float, default=5.0, help="Per-connection timeout (default 5s).")

    # Windows guest args
    win_group = p.add_argument_group("Windows Options")
    win_group.add_argument("--win-user", help="Windows guest username for WinRM (e.g. Administrator).")
    win_group.add_argument("--win-password", help="Windows guest password. Prefers env WIN_PASSWORD; prompts if neither.")
    win_group.add_argument("--win-auth", choices=("ntlm", "basic", "kerberos", "credssp"), default="ntlm",
                   help="WinRM auth mechanism (default ntlm).")
    win_group.add_argument("--win-transport", choices=("http", "https"), default="http",
                   help="WinRM transport (default http, port 5985).")
    win_group.add_argument("--win-port", type=int, default=None,
                   help="WinRM port (default 5985 for http, 5986 for https).")
    win_group.add_argument("--apply", action="store_true",
                   help="Actually apply Windows changes (default is dry-run).")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)

    print(f"{C.BLD}Palette VMO / VMA Pre-flight{C.RST}")
    print(f"  Run at: {time.strftime('%Y-%m-%d %H:%M:%S %Z').strip()}")
    print(f"  Host:   {socket.gethostname()}")

    # Was the run mode chosen on the command line, or do we need the menu?
    mode = args.run
    interactive = mode is None
    if interactive:
        mode = prompt_menu()
        if mode is None:
            print("Cancelled."); return 0
        # Interactive path: prompt for whatever the mode needs.
        if not interactive_fill(mode, args):
            print("Cancelled."); return 0

    # Merge --vm and --vm-file (whether from CLI or interactive prompt).
    err = resolve_vm_list(args)
    if err:
        head("Startup"); FAIL("Read --vm-file", err); return summary()

    # Resolve WinRM port default
    win_port = args.win_port
    if win_port is None:
        win_port = 5986 if args.win_transport == "https" else 5985

    # Any mode that hits vCenter needs --vcenter and --user
    needs_vcenter = mode in ("preflight", "allvms", "windows", "all")

    vcenter_host: Optional[str] = None
    vcenter_port: int = 443
    if args.vcenter:
        try:
            vcenter_host, vcenter_port = parse_endpoint(args.vcenter)
        except ValueError as e:
            head("Startup"); FAIL("Parse --vcenter", str(e)); return summary()

    vcenter_password = None
    if needs_vcenter:
        missing = []
        if not args.vcenter: missing.append("--vcenter")
        if not args.user:    missing.append("--user")
        if missing:
            head("Startup")
            FAIL("vCenter credentials", f"'{mode}' requires: {', '.join(missing)}")
            print_mode_example_hint(mode)
            return summary()
        try:
            import pyVim.connect  # noqa: F401
        except ImportError:
            head("Startup")
            FAIL("pyvmomi not installed", "pip install pyvmomi")
            return summary()
        vcenter_password = args.password or os.environ.get("VC_PASSWORD")
        if not vcenter_password:
            try:
                vcenter_password = getpass.getpass(f"vCenter password for {args.user}: ")
            except (EOFError, KeyboardInterrupt):
                head("Startup"); FAIL("Password prompt", "no password provided")
                print_mode_example_hint(mode); return summary()

    # Modes that need --vm (or --vm-file) to do anything meaningful.
    if mode in ("allvms", "windows", "all") and not args.vm:
        head("Startup")
        FAIL("No VMs specified", f"'{mode}' requires at least one --vm NAME or --vm-file PATH")
        print_mode_example_hint(mode)
        return summary()

    # Windows mode needs --win-user.
    if mode in ("windows", "all") and not args.win_user:
        # For 'all', win-user only matters if the list contains Windows VMs;
        # we can't easily tell in advance, so warn (not fail) for 'all'.
        if mode == "windows":
            head("Startup")
            FAIL("Windows guest credentials", "'windows' requires --win-user USER")
            print_mode_example_hint(mode)
            return summary()
        else:
            print(f"  {C.YLW}Note:{C.RST} --win-user not set; Windows portion of '--run all' will FAIL if any VM in the list is Windows")

    # ---------- Dispatch ----------
    esxi_hosts: List[str] = list(dict.fromkeys(args.esxi))

    if mode in ("preflight", "all"):
        discovered = check_vcenter_preflight(
            host=vcenter_host, port=vcenter_port,
            user=args.user, password=vcenter_password,
            insecure=args.insecure, vm_names=args.vm or None,
            timeout=args.timeout,
            folder_paths=args.folder or None,
            per_vm_privs=args.per_vm_privs,
        )
        if discovered:
            for h in discovered:
                if h not in esxi_hosts:
                    esxi_hosts.append(h)

        if not args.skip_dns:
            names: List[str] = []
            if vcenter_host: names.append(vcenter_host)
            for h in esxi_hosts:
                if h and h not in names: names.append(h)
            if names:
                check_dns(names)
            else:
                head("D. DNS resolution"); SKIP("DNS resolution", "no targets")
        else:
            head("D. DNS resolution"); SKIP("DNS resolution", "SKIPPED")

        if not args.skip_ports:
            targets: List[Tuple[str, int]] = []
            if vcenter_host: targets.append((vcenter_host, vcenter_port or 443))
            for h in esxi_hosts: targets.append((h, 902))
            check_ports(targets, args.timeout)
        else:
            head("E.TCP port reachability (timeout 5s) "); SKIP("TCP port test", "SKIPPED")

    if mode in ("allvms", "all"):
        run_allvms_checks(
            host=vcenter_host, port=vcenter_port,
            user=args.user, password=vcenter_password,
            insecure=args.insecure, vm_names=args.vm or None,
            timeout=args.timeout,
        )

    if mode in ("windows", "all"):
        run_windows_checks(
            host=vcenter_host, port=vcenter_port,
            user=args.user, password=vcenter_password,
            insecure=args.insecure, vm_names=args.vm or None,
            timeout=args.timeout,
            win_user=args.win_user, win_password=args.win_password,
            win_auth=args.win_auth, win_transport=args.win_transport, win_port=win_port,
            apply_changes=args.apply,
        )

    return summary()


if __name__ == "__main__":
    sys.exit(main())

