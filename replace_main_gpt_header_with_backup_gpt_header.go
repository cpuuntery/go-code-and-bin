package main

import (
    "bytes"
    "encoding/binary"
    "fmt"
    "hash/crc32"
    "log"
    "os"
)

const (
    SECTOR_SIZE = 512
)

// GPTHeader models the first 92 bytes of a GPT header
type GPTHeader struct {
    Signature          [8]byte // "EFI PART"
    Revision           uint32
    HeaderSize         uint32
    HeaderCRC32        uint32
    Reserved           uint32
    CurrentLBA         uint64
    BackupLBA          uint64
    FirstUsableLBA     uint64
    LastUsableLBA      uint64
    DiskGUID           [16]byte
    PartitionTableLBA  uint64
    NumPartitions      uint32
    PartitionEntrySize uint32
    PartitionTableCRC  uint32
}

func main() {
    if len(os.Args) < 2 {
        fmt.Fprintf(os.Stderr, "usage: %s <disk-or-image>\n", os.Args[0])
        os.Exit(1)
    }
    path := os.Args[1]

    f, err := os.OpenFile(path, os.O_RDWR, 0)
    if err != nil {
        log.Fatalf("open %q: %v", path, err)
    }
    defer f.Close()

    fi, err := f.Stat()
    if err != nil {
        log.Fatalf("stat %q: %v", path, err)
    }
    fileSize := fi.Size()
    if fileSize%SECTOR_SIZE != 0 {
        log.Fatalf("file size %d not a multiple of %d", fileSize, SECTOR_SIZE)
    }
    totalSectors := uint64(fileSize / SECTOR_SIZE)

    // 1) Read & parse primary header at LBA 1
    primHdrOff := int64(SECTOR_SIZE * 1)
    primHdrBuf := make([]byte, SECTOR_SIZE)
    if _, err := f.ReadAt(primHdrBuf, primHdrOff); err != nil {
        log.Fatalf("read primary header: %v", err)
    }
    var primary GPTHeader
    if err := binary.Read(bytes.NewReader(primHdrBuf), binary.LittleEndian, &primary); err != nil {
        log.Fatalf("decode primary header: %v", err)
    }

    // 2) Read primary partition array
    entrySize := int(primary.PartitionEntrySize)
    numEntries := int(primary.NumPartitions)
    tableBytes := int64(numEntries * entrySize)
    primTableOff := int64(primary.PartitionTableLBA) * SECTOR_SIZE

    if primTableOff+tableBytes > fileSize {
        log.Fatalf("primary partition table (off %d, size %d) beyond file size %d",
            primTableOff, tableBytes, fileSize)
    }
    tableBuf := make([]byte, tableBytes)
    if _, err := f.ReadAt(tableBuf, primTableOff); err != nil {
        log.Fatalf("read primary entries: %v", err)
    }

    // 3) Re-align partitions immediately after FirstUsableLBA
    curStart := primary.FirstUsableLBA
    for i := 0; i < numEntries; i++ {
        off := i * entrySize
        entry := tableBuf[off : off+entrySize]

        oldStart := binary.LittleEndian.Uint64(entry[32:40])
        oldEnd := binary.LittleEndian.Uint64(entry[40:48])
        if oldEnd == 0 || oldStart == 0 {
            // empty entry
            continue
        }

        size := oldEnd - oldStart + 1
        newStart := curStart
        newEnd := newStart + size - 1

        binary.LittleEndian.PutUint64(entry[32:40], newStart)
        binary.LittleEndian.PutUint64(entry[40:48], newEnd)

        curStart = newEnd + 1
    }

    // 4) Write updated primary partition array back
    if _, err := f.WriteAt(tableBuf, primTableOff); err != nil {
        log.Fatalf("write primary entries: %v", err)
    }
    // Recalculate CRC of partition array
    tableCRC := crc32.ChecksumIEEE(tableBuf)
    primary.PartitionTableCRC = tableCRC

    // 5) Recompute primary header fields for actual image size
    partSectors := uint64((tableBytes + SECTOR_SIZE - 1) / SECTOR_SIZE)
    backupHdrLBA := totalSectors - 1
    primary.BackupLBA = backupHdrLBA
    primary.LastUsableLBA = backupHdrLBA - partSectors - 1

    // 6) Serialize & CRC primary header
    buf := new(bytes.Buffer)
    if err := binary.Write(buf, binary.LittleEndian, primary); err != nil {
        log.Fatalf("serialize primary header: %v", err)
    }
    hdrBytes := buf.Bytes()
    if len(hdrBytes) < int(primary.HeaderSize) {
        hdrBytes = append(hdrBytes, make([]byte, int(primary.HeaderSize)-len(hdrBytes))...)
    }
    for i := 16; i < 20; i++ {
        hdrBytes[i] = 0
    }
    primCRC := crc32.ChecksumIEEE(hdrBytes[:primary.HeaderSize])
    binary.LittleEndian.PutUint32(hdrBytes[16:20], primCRC)

    // 7) Write corrected primary header back to LBA 1
    if _, err := f.WriteAt(hdrBytes[:primary.HeaderSize], primHdrOff); err != nil {
        log.Fatalf("write primary header: %v", err)
    }
    fmt.Printf("primary header updated: BackupLBA=%d, LastUsableLBA=%d, CRC=0x%08x\n",
        primary.BackupLBA, primary.LastUsableLBA, primCRC)

    // 8) Build backup partition array & header at end
    backupTableLBA := backupHdrLBA - partSectors
    backupTableOff := int64(backupTableLBA) * SECTOR_SIZE
    if _, err := f.WriteAt(tableBuf, backupTableOff); err != nil {
        log.Fatalf("write backup entries: %v", err)
    }

    backup := primary
    backup.CurrentLBA = backupHdrLBA
    backup.BackupLBA = 1
    backup.PartitionTableLBA = backupTableLBA
    backup.PartitionTableCRC = tableCRC

    // Serialize & CRC backup header
    bbuf := new(bytes.Buffer)
    if err := binary.Write(bbuf, binary.LittleEndian, backup); err != nil {
        log.Fatalf("serialize backup header: %v", err)
    }
    bHdr := bbuf.Bytes()
    if len(bHdr) < int(backup.HeaderSize) {
        bHdr = append(bHdr, make([]byte, int(backup.HeaderSize)-len(bHdr))...)
    }
    for i := 16; i < 20; i++ {
        bHdr[i] = 0
    }
    backCRC := crc32.ChecksumIEEE(bHdr[:backup.HeaderSize])
    binary.LittleEndian.PutUint32(bHdr[16:20], backCRC)

    // Write backup header to last sector
    backupHdrOff := int64(backupHdrLBA) * SECTOR_SIZE
    if _, err := f.WriteAt(bHdr[:backup.HeaderSize], backupHdrOff); err != nil {
        log.Fatalf("write backup header: %v", err)
    }
    fmt.Printf("backup header updated: CurrentLBA=%d, BackupLBA=%d, CRC=0x%08x\n",
        backup.CurrentLBA, backup.BackupLBA, backCRC)

    fmt.Println("All partitions shifted immediately after primary GPT header; sizes unchanged.")
}
