package main

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "hash/crc32"
    "log"
    "os"
)

const (
    SECTOR_SIZE = 512
)

// GPTHeader covers the first 92 bytes of a GPT header
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

    f, err := os.Open(path)
    if err != nil {
        log.Fatalf("failed to open %q: %v", path, err)
    }
    defer f.Close()

    // Read LBA 1 (GPT primary header)
    hdrBuf := make([]byte, SECTOR_SIZE)
    if _, err := f.ReadAt(hdrBuf, SECTOR_SIZE); err != nil {
        log.Fatalf("read header: %v", err)
    }

    // Decode into struct
    var hdr GPTHeader
    if err := binary.Read(bytes.NewReader(hdrBuf), binary.LittleEndian, &hdr); err != nil {
        log.Fatalf("decode header: %v", err)
    }

    // Recalculate Header CRC32
    origHdrCRC := hdr.HeaderCRC32
    hdrForCRC := make([]byte, hdr.HeaderSize)
    copy(hdrForCRC, hdrBuf[:hdr.HeaderSize])
    // zero out stored CRC bytes (offset 16–19)
    for i := 16; i < 20; i++ {
        hdrForCRC[i] = 0
    }
    calcHdrCRC := crc32.ChecksumIEEE(hdrForCRC)

    // Read and CRC the partition entry array
    tableSize := int64(hdr.NumPartitions) * int64(hdr.PartitionEntrySize)
    partOffset := int64(hdr.PartitionTableLBA) * SECTOR_SIZE
    partBuf := make([]byte, tableSize)
    if _, err := f.ReadAt(partBuf, partOffset); err != nil {
        log.Fatalf("read partition entries: %v", err)
    }
    calcTableCRC := crc32.ChecksumIEEE(partBuf)

    // Print with the same layout you posted
    fmt.Printf("Signature:                                              0x%s\n",
        hex.EncodeToString(hdr.Signature[:]))
    fmt.Printf("Revision:                                                       0x%08x\n",
        hdr.Revision)
    fmt.Printf("HeaderSize:                                                             %d\n",
        hdr.HeaderSize)
    fmt.Printf("HeaderCRC32:                                                    0x%08x\n",
        origHdrCRC)
    fmt.Printf("HeaderCRC32 (calculated):                                       0x%08x\n",
        calcHdrCRC)
    fmt.Printf("Reserved:                                                       0x%08x\n",
        hdr.Reserved)
    fmt.Printf("MyLBA:                                                                   %d\n",
        hdr.CurrentLBA)
    fmt.Printf("AlternateLBA:                                                       %d\n",
        hdr.BackupLBA)
    fmt.Printf("FirstUsableLBA:                                                         %d\n",
        hdr.FirstUsableLBA)
    fmt.Printf("LastUsableLBA:                                                      %d\n",
        hdr.LastUsableLBA)
    fmt.Printf("PartitionEntryLBA:                                                       %d\n",
        hdr.PartitionTableLBA)
    fmt.Printf("NumberOfPartitionEntries:                                              %d\n",
        hdr.NumPartitions)
    fmt.Printf("SizeOfPartitionEntry:                                                  %d\n",
        hdr.PartitionEntrySize)
    fmt.Printf("PartitionEntryArrayCRC32:                                       0x%08x\n",
        hdr.PartitionTableCRC)
    fmt.Printf("PartitionEntryArrayCRC32 (calculated):                          0x%08x\n",
        calcTableCRC)
}
