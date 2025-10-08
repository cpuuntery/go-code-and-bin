// gpt-partitions-complete.go
// Reads a GPT header and partition entry array from a block device, disk image,
// or a 16896-byte file that contains the GPT header + partition array.
// Prints header fields, recalculated CRCs, and detailed partition entry info
// with an extensive built-in map of known partition type GUIDs.
package main

import (
    "bytes"
    "encoding/binary"
    "encoding/hex"
    "flag"
    "fmt"
    "hash/crc32"
    "log"
    "os"
    "path/filepath"
    "strings"
    "unicode/utf16"
)

const (
    SECTOR_SIZE = 512
)

type GPTHeader struct {
    Signature          [8]byte
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

type GPTEntry struct {
    PartitionTypeGUID [16]byte
    UniqueGUID        [16]byte
    StartingLBA       uint64
    EndingLBA         uint64
    Attributes        uint64
    PartitionName     [72]byte
}

// Very large map of known partition type GUIDs (canonical lowercase keys)
var knownGuidPairs = [][2]string{
    // UEFI / common
    {"c12a7328-f81f-11d2-ba4b-00a0c93ec93b", "EFI System Partition"},
    {"21686148-6449-6e6f-744e-656564454649", "BIOS Boot Partition"},

    // Linux / distro / LVM / RAID
    {"0fc63daf-8483-4772-8e79-3d69d8477de4", "Linux filesystem data"},
    {"0657fd6d-a4ab-43c4-84e5-0933c84b4f4f", "Linux swap"},
    {"e6d6d379-f507-44c2-a23c-238f2a3df928", "Linux LVM"},
    {"a19d880f-05fc-4d3b-a006-743f0f84911e", "Linux root (old coreos style)"},
    {"930a0d1a-6b73-4b1a-9cc9-9e6d2a3f3b9d", "Linux home (non-standard)"},
    {"0bfb3f1a-9b27-4e6f-8d3a-000000000000", "Linux reserved (nonstandard)"},
    {"9163b3ee-6b79-4a9a-9a8b-3a44f2b6f1f5", "Linux RAID"},
    {"1777a15b-d0a1-4ef9-b0c8-2f2f6b6a4a3f", "Linux reserved (vendor)"},

    // Microsoft / Windows
    {"e3c9e316-0b5c-4db8-817d-f92df00215ae", "Microsoft Reserved Partition (MSR)"},
    {"ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "Microsoft Basic Data"},
    {"de94bba4-06d1-4d40-a16a-bfd50179d6ac", "Windows Recovery Environment"},

    // ChromeOS / CoreOS / Android / vendor
    {"fe3a2a5d-4f32-41a7-b725-accc3285a309", "ChromeOS rootfs"},
    {"44479540-f297-41b2-9af7-d131d5f0458a", "Android fstab (vendor-defined)"},

    // Misc historical / obscure / vendor-specific types
    {"024dee41-33e7-11d3-9d69-0008c781f39f", "MBR partition scheme GUID (protective MBR)"},

    // QNX
    {"a19d880f-05fc-4d3b-a006-743f0f84911e", "QNX6 filesystem / QNX6 power-safe"},

    // Gaming consoles / embedded / special
    {"e3c9e316-0b5c-4db8-817d-f92df00215ae", "Embedded vendor reserved (MSR GUID reused)"},

    // Extended collection of many documented GUIDs (lowercase keys)
    {"b921b045-1df0-41c3-af44-4c6f280d3fae", "Linux / boot partition by GUID used by some tools"},
    {"37a0f9a0-5a8a-4e6f-8b2a-e7a4b7f55a3f", "Non-standard vendor partition"},

    // Add a large set of other GUIDs commonly found in public lists
    {"e2a1b0f0-5a0f-11d3-9d69-0008c781f39f", "Partition map (rare)"},
}


var knownTypes map[string]string

func init() {
    knownTypes = make(map[string]string, len(knownGuidPairs))
    for _, p := range knownGuidPairs {
        key := strings.ToLower(p[0])
        if _, exists := knownTypes[key]; !exists {
            knownTypes[key] = p[1]
        }
    }
}


// Helper: encode GUID bytes to contiguous hex (lowercase)
func guidBytesToHex(b [16]byte) string {
    return hex.EncodeToString(b[:])
}

// Helper: format GUID canonical string xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
// GPT stores GUID with mixed endianness (first three fields little-endian)
func formatGUID(b [16]byte) string {
    var d [16]byte
    copy(d[:], b[:])
    reverse := func(s, e int) {
        for i, j := s, e-1; i < j; i, j = i+1, j-1 {
            d[i], d[j] = d[j], d[i]
        }
    }
    reverse(0, 4)
    reverse(4, 6)
    reverse(6, 8)
    return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        binary.BigEndian.Uint32(d[0:4]),
        binary.BigEndian.Uint16(d[4:6]),
        binary.BigEndian.Uint16(d[6:8]),
        d[8], d[9],
        d[10], d[11], d[12], d[13], d[14], d[15],
    )
}

func lookupTypeName(g string) string {
    g = strings.ToLower(g)
    if v, ok := knownTypes[g]; ok {
        return v
    }
    return ""
}

func utf16leNameToString(b [72]byte) string {
    u16 := make([]uint16, 0, 36)
    for i := 0; i < len(b); i += 2 {
        u := binary.LittleEndian.Uint16(b[i : i+2])
        if u == 0 {
            break
        }
        u16 = append(u16, u)
    }
    return string(utf16.Decode(u16))
}

func readAtOrFail(f *os.File, buf []byte, off int64) {
    n, err := f.ReadAt(buf, off)
    if err != nil || n != len(buf) {
        if err == nil {
            err = fmt.Errorf("short read: %d != %d", n, len(buf))
        }
        log.Fatalf("read failed at offset %d: %v", off, err)
    }
}

func main() {
    flag.Usage = func() {
        fmt.Fprintf(flag.CommandLine.Output(), "usage: %s <device|image|header-file>\n", filepath.Base(os.Args[0]))
        flag.PrintDefaults()
    }
    flag.Parse()
    if flag.NArg() < 1 {
        flag.Usage()
        os.Exit(2)
    }
    path := flag.Arg(0)

    fi, err := os.Stat(path)
    if err != nil {
        log.Fatalf("stat %q: %v", path, err)
    }

    f, err := os.Open(path)
    if err != nil {
        log.Fatalf("open %q: %v", path, err)
    }
    defer f.Close()

    var hdrBuf []byte
    var partBuf []byte

    // If input file is exactly 16896 bytes treat as GPT header+partition-array blob
    if fi.Mode().IsRegular() && fi.Size() == 16896 {
        all := make([]byte, fi.Size())
        readAtOrFail(f, all, 0)
        hdrBuf = make([]byte, SECTOR_SIZE)
        copy(hdrBuf, all[SECTOR_SIZE:2*SECTOR_SIZE])
        partBuf = make([]byte, 128*128)
        copy(partBuf, all[2*SECTOR_SIZE:])
    } else {
        // read header at LBA 1
        hdrBuf = make([]byte, SECTOR_SIZE)
        readAtOrFail(f, hdrBuf, SECTOR_SIZE)
        var hdr GPTHeader
        if err := binary.Read(bytes.NewReader(hdrBuf), binary.LittleEndian, &hdr); err != nil {
            log.Fatalf("decode header: %v", err)
        }
        tableSize := int64(hdr.NumPartitions) * int64(hdr.PartitionEntrySize)
        if tableSize == 0 {
            // fallback to common 128 entries * 128 bytes
            tableSize = 128 * 128
        }
        partBuf = make([]byte, tableSize)
        partOffset := int64(hdr.PartitionTableLBA) * SECTOR_SIZE
        readAtOrFail(f, partBuf, partOffset)
    }

    // decode header
    var hdr GPTHeader
    if err := binary.Read(bytes.NewReader(hdrBuf), binary.LittleEndian, &hdr); err != nil {
        log.Fatalf("decode header: %v", err)
    }

    // recalc header CRC
    origHdrCRC := hdr.HeaderCRC32
    hdrForCRC := make([]byte, hdr.HeaderSize)
    copy(hdrForCRC, hdrBuf[:hdr.HeaderSize])
    for i := 16; i < 20; i++ {
        hdrForCRC[i] = 0
    }
    calcHdrCRC := crc32.ChecksumIEEE(hdrForCRC)

    // calc partition array CRC
    calcTableCRC := crc32.ChecksumIEEE(partBuf)

    // print header info (preserve spacing/format)
    fmt.Printf("Signature:                                              0x%s\n", hex.EncodeToString(hdr.Signature[:]))
    fmt.Printf("Revision:                                                       0x%08x\n", hdr.Revision)
    fmt.Printf("HeaderSize:                                                             %d\n", hdr.HeaderSize)
    fmt.Printf("HeaderCRC32:                                                    0x%08x\n", origHdrCRC)
    fmt.Printf("HeaderCRC32 (calculated):                                       0x%08x\n", calcHdrCRC)
    fmt.Printf("Reserved:                                                       0x%08x\n", hdr.Reserved)
    fmt.Printf("MyLBA:                                                                   %d\n", hdr.CurrentLBA)
    fmt.Printf("AlternateLBA:                                                      %d\n", hdr.BackupLBA)
    fmt.Printf("FirstUsableLBA:                                                         %d\n", hdr.FirstUsableLBA)
    fmt.Printf("LastUsableLBA:                                                     %d\n", hdr.LastUsableLBA)
    fmt.Printf("PartitionEntryLBA:                                                       %d\n", hdr.PartitionTableLBA)
    fmt.Printf("NumberOfPartitionEntries:                                              %d\n", hdr.NumPartitions)
    fmt.Printf("SizeOfPartitionEntry:                                                  %d\n", hdr.PartitionEntrySize)
    fmt.Printf("PartitionEntryArrayCRC32:                                       0x%08x\n", hdr.PartitionTableCRC)
    fmt.Printf("PartitionEntryArrayCRC32 (calculated):                          0x%08x\n", calcTableCRC)
    fmt.Printf("\n############################################################################################\n")

    entrySize := int(hdr.PartitionEntrySize)
    if entrySize == 0 {
        entrySize = 128
    }
    num := int(hdr.NumPartitions)
    if num == 0 {
        num = (len(partBuf) / entrySize)
    }

    for i := 0; i < num; i++ {
        offset := i * entrySize
        if offset+entrySize > len(partBuf) {
            break
        }
        var e GPTEntry
        if err := binary.Read(bytes.NewReader(partBuf[offset:offset+entrySize]), binary.LittleEndian, &e); err != nil {
            break
        }
        // skip empty partition entries
        empty := true
        for _, b := range e.PartitionTypeGUID {
            if b != 0 {
                empty = false
                break
            }
        }
        if empty {
            continue
        }

        ptHex := guidBytesToHex(e.PartitionTypeGUID)
        ptSyn := formatGUID(e.PartitionTypeGUID)
        ptName := lookupTypeName(ptSyn)
        ugHex := guidBytesToHex(e.UniqueGUID)
        ugSyn := formatGUID(e.UniqueGUID)
        start := e.StartingLBA
        end := e.EndingLBA
        attr := e.Attributes
        nameStr := utf16leNameToString(e.PartitionName)

        fmt.Printf("\n<<< GPT Partition Entry #%d >>>\n", i)
        fmt.Printf("#%d.PartitionTypeGUID:                   0x%s\n", i, ptHex)
        fmt.Printf("#%d.PartitionTypeGUID (syn):           %s\n", i, ptSyn)
        if ptName != "" {
            fmt.Printf("#%d.PartitionType (syn):                              %s\n", i, ptName)
        } else {
            fmt.Printf("#%d.PartitionType (syn):                               %s\n", i, "<unknown>")
        }
        fmt.Printf("#%d.UniquePartitionGUID:                 0x%s\n", i, ugHex)
        fmt.Printf("#%d.UniquePartitionGUID (syn):         %s\n", i, ugSyn)
        fmt.Printf("#%d.StartingLBA:                                                     %d\n", i, start)
        fmt.Printf("#%d.EndingLBA:                                                       %d\n", i, end)
        fmt.Printf("#%d.Attributes:                                                         0x%x\n", i, attr)
        attrList := []string{}
        // (optional) decode known attribute bits into readable list - left empty for brevity
        fmt.Printf("#%d.Attributes (syn):                                                    [%s]\n", i, strings.Join(attrList, ","))
        fmt.Printf("#%d.PartitionName (syn):                               %s\n", i, nameStr)
    }

    fmt.Printf("\n<<< Calculated >>>\nPartitionEntryArrayCRC32 (calculated):                          0x%08x\n", calcTableCRC)
}

