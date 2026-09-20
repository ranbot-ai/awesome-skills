---
name: block-storage
description: Manage block storage volumes and LVM. Configure cloud block storage and local disks. Use when managing disk storage. 
category: AI & Agents
source: antigravity
tags: [ai, agent, gpt, template, security, stripe, aws, rag, cro]
url: https://github.com/sickn33/antigravity-awesome-skills/tree/main/skills/block-storage
---


# Block Storage

Manage block storage volumes including LVM, cloud-based EBS, filesystem creation, snapshots, and RAID configurations. Covers the full lifecycle from provisioning raw disks to extending volumes in production.

## When to Use

- Adding, partitioning, or formatting new disks on Linux servers
- Managing LVM logical volumes for flexible storage allocation
- Provisioning and attaching cloud block storage (AWS EBS)
- Creating and restoring snapshots for backup or migration
- Configuring software RAID for redundancy or performance
- Extending existing volumes without downtime

## Prerequisites

- Root or sudo access on the target system
- `lvm2` package installed for LVM operations
- `mdadm` package installed for software RAID
- AWS CLI configured for EBS operations
- Understanding of the workload's I/O characteristics (IOPS, throughput)

## Disk Discovery and Partitioning

```bash
# List all block devices
lsblk
lsblk -f    # Show filesystem types and mount points

# Show detailed disk information
fdisk -l /dev/sdb

# Identify disk model and health (requires smartmontools)
smartctl -a /dev/sda
smartctl -H /dev/sda    # Quick health check

# Create a GPT partition table and a single partition
parted /dev/sdb mklabel gpt
parted /dev/sdb mkpart primary ext4 0% 100%

# Alternative: use fdisk for MBR partitioning
fdisk /dev/sdb
# n -> new partition, p -> primary, Enter defaults, w -> write

# Inform the kernel of partition table changes
partprobe /dev/sdb

# Wipe filesystem signatures (prepare for LVM or RAID)
wipefs -a /dev/sdb1
```

## Filesystem Creation and Management

```bash
# Create an ext4 filesystem
mkfs.ext4 /dev/sdb1

# Create an ext4 filesystem with label and reserved block tuning
mkfs.ext4 -L appdata -m 1 /dev/sdb1    # 1% reserved blocks (default is 5%)

# Create an XFS filesystem (recommended for large volumes)
mkfs.xfs /dev/sdb1

# Create an XFS filesystem with label
mkfs.xfs -L appdata /dev/sdb1

# Mount the filesystem
mkdir -p /data
mount /dev/sdb1 /data

# Add persistent mount to fstab (use UUID for reliability)
blkid /dev/sdb1    # Get the UUID
echo 'UUID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  /data  ext4  defaults,noatime  0  2' >> /etc/fstab

# Mount all entries in fstab
mount -a

# Check and repair a filesystem (unmount first)
umount /data
fsck.ext4 -y /dev/sdb1
xfs_repair /dev/sdb1    # For XFS

# Resize ext4 (can grow online while mounted)
resize2fs /dev/sdb1

# Resize XFS (must be mounted to grow)
xfs_growfs /data

# Check filesystem usage
df -hT
```

## LVM Management

### Creating an LVM Stack

```bash
# Step 1: Create physical volumes
pvcreate /dev/sdb /dev/sdc

# View physical volumes
pvs
pvdisplay /dev/sdb

# Step 2: Create a volume group from physical volumes
vgcreate data_vg /dev/sdb /dev/sdc

# View volume groups
vgs
vgdisplay data_vg

# Step 3: Create logical volumes
# Fixed size
lvcreate -L 100G -n app_lv data_vg

# Use percentage of free space
lvcreate -l 50%FREE -n logs_lv data_vg

# Use all remaining space
lvcreate -l 100%FREE -n backup_lv data_vg

# View logical volumes
lvs
lvdisplay /dev/data_vg/app_lv

# Step 4: Create filesystem and mount
mkfs.ext4 /dev/data_vg/app_lv
mkdir -p /data/app
mount /dev/data_vg/app_lv /data/app

# Add to fstab
echo '/dev/data_vg/app_lv  /data/app  ext4  defaults,noatime  0  2' >> /etc/fstab
```

### Extending Volumes (Online)

```bash
# Extend a logical volume by 20 GB
lvextend -L +20G /dev/data_vg/app_lv

# Extend to fill all free space in the VG
lvextend -l +100%FREE /dev/data_vg/app_lv

# Grow the ext4 filesystem (online, no unmount needed)
resize2fs /dev/data_vg/app_lv

# Grow XFS filesystem (online)
xfs_growfs /data/app

# Combined: extend LV and resize filesystem in one command
lvextend -L +20G --resizefs /dev/data_vg/app_lv
```

### Adding a New Disk to an Existing VG

```bash
# Add a new physical volume
pvcreate /dev/sdd

# Extend the volume group
vgextend data_vg /dev/sdd

# Now extend any logical volume using the new space
lvextend -l +100%FREE --resizefs /dev/data_vg/app_lv
```

### LVM Snapshots

```bash
# Create a snapshot (requires free space in VG)
lvcreate -L 10G -s -n app_snap /dev/data_vg/app_lv

# Mount the snapshot read-only for backup
mkdir -p /mnt/snapshot
mount -o ro /dev/data_vg/app_snap /mnt/snapshot

# Perform backup from the snapshot
tar czf /backup/app-$(date +%Y%m%d).tar.gz -C /mnt/snapshot .

# Unmount and remove the snapshot when done
umount /mnt/snapshot
lvremove -f /dev/data_vg/app_snap

# Restore from snapshot (reverts LV to snapshot point -- destructive)
lvconvert --merge /dev/data_vg/app_snap
# Note: if the LV is mounted, merge happens at next activation (reboot)
```

### Reducing and Removing LVM Components

```bash
# Shrink a logical volume (ext4 only -- XFS cannot shrink)
# MUST unmount first
umount /data/app
e2fsck -f /dev/data_vg/app_lv
resize2fs /dev/data_vg/app_lv 80G
lvreduce -L 80G /dev/data_vg/app_lv
mount /data/app

# Remove a logical volume
umount /data/app
lvremove /dev/data_vg/app_lv
