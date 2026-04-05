# Troubleshooting

## FUSE mount fails with "Permission denied" on Ubuntu 24.04+

### Symptom

Running `p9n-importer` as a non-root user fails with:

```
/usr/bin/fusermount3: mount failed: Permission denied
```

Even though `/dev/fuse` permissions (`crw-rw-rw-`), `fusermount3` setuid bit, and the mount point permissions all look correct.

### Root Cause

Ubuntu 24.04+ enables AppArmor restriction on unprivileged user namespaces by default (`kernel.apparmor_restrict_unprivileged_userns = 1`). The bundled `fusermount3` AppArmor profile only allows mounting to a whitelist of paths (typically `/tmp/`, `/home/`, `/media/`, `/run/user/`). Mount points outside these paths (e.g. `/data/mnt/`) are denied.

You can confirm this by checking the kernel audit log:

```bash
journalctl -g "DENIED.*fuse" --no-pager -n 10
```

A matching entry looks like:

```
apparmor="DENIED" operation="mount" info="failed mntpnt match"
  profile="fusermount3" name="/data/mnt/" fstype="fuse"
```

### Solutions

**Option A: Use an allowed mount point**

Pick a path under `/home/` or `/tmp/`:

```bash
mkdir -p ~/mnt/9p
p9n-importer -e 127.0.0.1:5640 --mount ~/mnt/9p \
  --cert cert.pem --key key.pem --ca ca.pem
```

**Option B: Run as root**

`p9n-importer` detects root and calls `mount()` directly via `/dev/fuse`, bypassing `fusermount3` and AppArmor entirely:

```bash
sudo p9n-importer -e 127.0.0.1:5640 --mount /data/mnt \
  --cert cert.pem --key key.pem --ca ca.pem
```

**Option C: Extend the AppArmor profile**

Add your mount point to the fusermount3 profile:

```bash
# Check current profile
sudo cat /etc/apparmor.d/usr.bin.fusermount3

# Add a local override (survives package updates)
echo 'mount fstype=fuse options=(rw,nosuid,nodev) ** -> /data/**,' | \
  sudo tee -a /etc/apparmor.d/local/usr.bin.fusermount3

# Reload
sudo apparmor_parser -r /etc/apparmor.d/usr.bin.fusermount3
```

### How to verify

```bash
# Check AppArmor restriction is active
cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns
# 1 = restricted (Ubuntu 24.04+ default)

# Check recent denials
journalctl -g "DENIED.*fuse" --no-pager -n 5
```

## "Transport endpoint is not connected" (ENOTCONN) on startup

### Symptom

Starting `p9n-importer` fails immediately with:

```
Error: Os { code: 107, kind: NotConnected, message: "Transport endpoint is not connected" }
```

### Root Cause

A previous `p9n-importer` process exited (crashed, was killed, or Ctrl-C'd) without cleanly unmounting the FUSE filesystem. The mount point is now **stale**: it still appears in `/proc/mounts` but the backing daemon is gone. Any filesystem operation on the stale mount returns `ENOTCONN`, including `fuse3`'s mount-point readiness check when starting a new instance.

### Diagnosis

```bash
# Check for stale mount
cat /proc/mounts | grep fuse
# Look for an entry like:
#   9p mounted_path fuse rw,nosuid,nodev,relatime,...

# Confirm it's stale (should return ENOTCONN)
ls mounted_path
# ls: unknown io error: ... "Transport endpoint is not connected"

# Confirm the daemon is gone
ps aux | grep p9n-importer
```

### Fix

Unmount the stale FUSE mount, then retry:

```bash
# Non-root
fusermount3 -u mounted_path

# If fusermount3 is blocked by AppArmor
sudo umount mounted_path

# If even umount fails (very stuck), force with lazy unmount
sudo umount -l mounted_path
```

Then start `p9n-importer` again normally.
