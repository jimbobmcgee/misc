package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
)

// Minimal set of payload type constants
const (
	PT_NONE   = 0x00
	PT_SA     = 0x21
	PT_KE     = 0x22
	PT_IDi    = 0x23
	PT_IDr    = 0x24
	PT_AUTH   = 0x27
	PT_NONCE  = 0x28
	PT_NOTIFY = 0x29
	PT_TSi    = 0x2c
	PT_TSr    = 0x2d
	PT_SK     = 0x2e
)

// internal IANA Notify table (common values)
// NOTE: This is a curated subset of commonly seen notify codes (not exhaustive).
// Extend this map as needed. No external network calls are performed.
var notifyNames = map[uint16]string{
	0x0001: "UNSUPPORTED_CRITICAL_PAYLOAD",
	0x0002: "INVALID_IKE_SPI",
	0x0003: "INVALID_MAJOR_VERSION",
	0x0004: "INVALID_SYNTAX",
	0x0005: "INVALID_MESSAGE_ID",
	0x0006: "NO_PROPOSAL_CHOSEN",
	0x0007: "INVALID_KE_PAYLOAD",
	0x0008: "AUTHENTICATION_FAILED",
	0x0010: "FAILED_CP_REQUIRED",     // placeholder/common
	0x0013: "CERTIFICATE_UNAVAILABLE",
	0x0014: "AUTHENTICATION_FAILED_ALT",
	0x0026: "TS_UNACCEPTABLE",
	0x0030: "INVALID_CERT_ENCODING",
	0x0031: "INVALID_CERT_AUTHORITY",
	0x0032: "INVALID_CERT_SIGNATURE",
	0x0033: "DOI_NOT_SUPPORTED",
	0x0034: "SITUATION_NOT_SUPPORTED",
}

// Common transform ID/name mappings (ENCR/PRF/INTEG/DH). Curated subset.
var encrNames = map[uint16]string{
	12: "AES_CBC_128",
	13: "AES_CBC_192",
	14: "AES_CBC_256",
	18: "AES_GCM_16_128", // common GCM entry (vendor dependent)
	24: "CHACHA20_POLY1305", // vendor-assigned sometimes
}
var prfNames = map[uint16]string{
	2:  "PRF_HMAC_MD5",    // historic
	3:  "PRF_HMAC_SHA1",
	4:  "PRF_HMAC_TIGER",
	5:  "PRF_AES128_CMAC",
	6:  "PRF_HMAC_SHA2_256",
	7:  "PRF_HMAC_SHA2_384",
	8:  "PRF_HMAC_SHA2_512",
}
var integNames = map[uint16]string{
	1:  "AUTH_NONE",
	2:  "AUTH_HMAC_MD5_96",
	3:  "AUTH_HMAC_SHA1_96",
	12: "AUTH_HMAC_SHA2_256_128",
	13: "AUTH_HMAC_SHA2_384_192",
	14: "AUTH_HMAC_SHA2_512_256",
}
var dhNames = map[uint16]string{
	1:  "MODP_768",
	2:  "MODP_1024",
	5:  "MODP_1536",
	14: "MODP_2048",
	15: "MODP_3072",
	16: "MODP_4096",
	19: "ECP_256",
	20: "ECP_384",
	21: "ECP_521",
}

// user-specified match lists (populated from -match flag)
var matchCIDRs []*net.IPNet
var matchIPs []net.IP

func ianaNotifyName(code uint16) string {
	if n, ok := notifyNames[code]; ok {
		return n
	}
	return ""
}

// helpers
func cleanHex(s string) string {
	re := regexp.MustCompile("[^0-9a-fA-F]+")
	return re.ReplaceAllString(s, "")
}
func mustDecodeHex(s string) []byte {
	c := cleanHex(s)
	if len(c)%2 != 0 {
		c = "0" + c
	}
	b, err := hex.DecodeString(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hex decode error: %v\n", err)
		os.Exit(2)
	}
	return b
}
func be16(b []byte, off int) uint16 { return binary.BigEndian.Uint16(b[off : off+2]) }
func be32(b []byte, off int) uint32 { return binary.BigEndian.Uint32(b[off : off+4]) }
func u8(b []byte, off int) uint8    { return b[off] }
func hexSlice(b []byte, off, ln int) string {
	if off < 0 || off >= len(b) {
		return ""
	}
	if off+ln > len(b) {
		ln = len(b) - off
	}
	return strings.ToUpper(hex.EncodeToString(b[off:off+ln]))
}
func payloadName(t uint8) string {
	switch t {
	case PT_SA:
		return "SA"
	case PT_KE:
		return "KE"
	case PT_IDi:
		return "IDi"
	case PT_IDr:
		return "IDr"
	case PT_AUTH:
		return "AUTH"
	case PT_NONCE:
		return "NONCE"
	case PT_NOTIFY:
		return "NOTIFY"
	case PT_TSi:
		return "TSi"
	case PT_TSr:
		return "TSr"
	case PT_SK:
		return "SK (Encrypted)"
	default:
		return fmt.Sprintf("UNKNOWN(0x%02X)", t)
	}
}

func printIKEHeader(b []byte) int {
	if len(b) < 28 {
		fmt.Println("Buffer shorter than 28 bytes; no full IKE header present.")
		return 0
	}
	fmt.Println("IKE Header (offset 0..27):")
	fmt.Printf("  Initiator SPI: 0x%s\n", strings.ToUpper(hex.EncodeToString(b[0:8])))
	fmt.Printf("  Responder SPI: 0x%s\n", strings.ToUpper(hex.EncodeToString(b[8:16])))
	fmt.Printf("  Next Payload: 0x%02X (%s)\n", b[16], payloadName(b[16]))
	fmt.Printf("  Version: 0x%02X (Major %d, Minor %d)\n", b[17], b[17]>>4, b[17]&0x0F)
	fmt.Printf("  Exchange Type: 0x%02X\n", b[18])
	fmt.Printf("  Flags: 0x%02X\n", b[19])
	fmt.Printf("  Message ID: 0x%08X\n", be32(b, 20))
	fmt.Printf("  Length: %d bytes (0x%08X)\n", be32(b, 24), be32(b, 24))
	return 28
}

// Helpers to detect and format addresses found inside NOTIFY data
func extractIPv4List(data []byte) []uint32 {
	var out []uint32
	// If length is multiple of 4 and reasonable (4,8,12,16...), interpret 4-byte chunks as IPv4
	if len(data) >= 4 {
		if len(data)%4 == 0 {
			for i := 0; i+4 <= len(data); i += 4 {
				ip := be32(data, i)
				out = append(out, ip)
			}
		} else {
			// also try sliding window for cases where addresses may be embedded
			for i := 0; i+4 <= len(data); i += 1 {
				ip := be32(data, i)
				out = append(out, ip)
			}
		}
	}
	return out
}

func isPrivateIPv4(ip uint32) bool {
	b1 := byte(ip >> 24)
	b2 := byte(ip >> 16)
	// 10.0.0.0/8
	if b1 == 10 {
		return true
	}
	// 172.16.0.0/12
	if b1 == 172 && b2 >= 16 && b2 <= 31 {
		return true
	}
	// 192.168.0.0/16
	if b1 == 192 && b2 == 168 {
		return true
	}
	return false
}

func ipFromUint32(ip uint32) net.IP {
	return net.IPv4(byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip)).To4()
}

func matchIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, m := range matchCIDRs {
		if m.Contains(ip) {
			return true
		}
	}
	for _, p := range matchIPs {
		if p.Equal(ip) {
			return true
		}
	}
	return false
}

// NOTIFY
func parseNotify(b []byte, off, plen int) {
	if plen < 4 || off+4 > len(b) {
		fmt.Printf("  NOTIFY payload too short or truncated (plen=%d off=%d)\n", plen, off)
		return
	}
	proto := b[off]
	spiSize := b[off+1]
	nt := be16(b, off+2)
	fmt.Printf("  NOTIFY: Protocol ID=%d SPI Size=%d NotifyType=0x%04X (%d)", proto, spiSize, nt, nt)
	if nm := ianaNotifyName(nt); nm != "" {
		fmt.Printf(" name=%s", nm)
	}
	fmt.Println()
	dataOff := off + 4
	if int(spiSize) > 0 {
		if dataOff+int(spiSize) > len(b) {
			fmt.Printf("    SPI truncated\n")
			return
		}
		fmt.Printf("    SPI: 0x%s\n", strings.ToUpper(hex.EncodeToString(b[dataOff:dataOff+int(spiSize)])))
		dataOff += int(spiSize)
	}
	if dataOff < off+plen {
		ndata := b[dataOff:off+plen]
		fmt.Printf("    Notification Data (%d bytes): 0x%s\n", len(ndata), strings.ToUpper(hex.EncodeToString(ndata)))
		// Heuristic: look for IPv4/IPv6 addresses in the notification data and highlight them as possible NAT mappings
		// IPv4: if data length is a multiple of 4, treat each 4-byte chunk as an IPv4 address
		ipv4s := extractIPv4List(ndata)
		if len(ipv4s) > 0 {
			fmt.Printf("    Possible IPv4 addresses in notify data (%d):\n", len(ipv4s))
			for i, ipnum := range ipv4s {
				ipstr := ipv4String(ipnum)
				ip := ipFromUint32(ipnum)
				priv := ""
				if isPrivateIPv4(ipnum) {
					priv = " (private)"
				}
				match := ""
				if matchIP(ip) {
					match = " [MATCH]"
				}
				fmt.Printf("      - %s%s%s\n", ipstr, priv, match)
				// if not multiple-of-4 length, avoid indexing beyond
				_ = i
			}
			// if exact duplicate addresses present, highlight
			if len(ipv4s) >= 2 && ipv4s[0] == ipv4s[len(ipv4s)-1] {
				fmt.Printf("    Note: first and last IPv4 addresses are identical (%s) — common in NAT-D notifications\n", ipv4String(ipv4s[0]))
			}
		}
		// IPv6: if data length divisible by 16, extract 16-byte chunks
		if len(ndata)%16 == 0 && len(ndata) >= 16 {
			cnt := len(ndata) / 16
			fmt.Printf("    Possible IPv6 addresses in notify data (%d):\n", cnt)
			for i := 0; i < cnt; i++ {
				addr := ndata[i*16 : i*16+16]
				nip := net.IP(addr)
				match := ""
				if matchIP(nip) {
					match = " [MATCH]"
				}
				fmt.Printf("      - %s%s\n", ipv6String(addr), match)
			}
		}
	}
}

// AUTH
func parseAuth(b []byte, off, plen int) {
	if plen < 4 || off+4 > len(b) {
		fmt.Printf("  AUTH payload too short or truncated (plen=%d off=%d)\n", plen, off)
		return
	}
	method := b[off]
	reserved := b[off+1 : off+4]
	authData := []byte{}
	if off+4 < off+plen && off+4 < len(b) {
		end := off + plen
		if end > len(b) {
			end = len(b)
		}
		authData = b[off+4 : end]
	}
	fmt.Printf("  AUTH: Method=0x%02X Reserved=0x%s AuthData(%d bytes)=0x%s\n",
		method, strings.ToUpper(hex.EncodeToString(reserved)), len(authData), strings.ToUpper(hex.EncodeToString(authData)))
}

// ID
func parseID(b []byte, off, plen int) {
	if plen < 4 || off+4 > len(b) {
		fmt.Printf("  ID payload too short or truncated\n")
		return
	}
	idtype := b[off]
	iddata := []byte{}
	if off+4 < off+plen && off+4 < len(b) {
		end := off + plen
		if end > len(b) {
			end = len(b)
		}
		iddata = b[off+4 : end]
	}
	fmt.Printf("  ID: Type=0x%02X Data(%d bytes)=0x%s\n", idtype, len(iddata), strings.ToUpper(hex.EncodeToString(iddata)))
}

func ipv4String(u uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}
func ipv6String(bv []byte) string {
	if len(bv) != 16 {
		return fmt.Sprintf("len=%d bytes", len(bv))
	}
	parts := make([]uint16, 8)
	for i := 0; i < 8; i++ {
		parts[i] = binary.BigEndian.Uint16(bv[i*2 : i*2+2])
	}
	hexParts := make([]string, 8)
	for i := 0; i < 8; i++ {
		hexParts[i] = fmt.Sprintf("%x", parts[i])
	}
	return strings.Join(hexParts, ":")
}

// Traffic Selector parsing (normal deterministic parse)
func parseTS(b []byte, off, plen int, doResync bool) {
	if plen < 4 || off+4 > len(b) {
		fmt.Printf("  TS payload too short or truncated\n")
		return
	}
	numTS := b[off]
	reserved := b[off+1]
	length := be16(b, off+2)
	fmt.Printf("  TS Header: NumTS=%d Reserved=0x%02X Length=%d (payload plen=%d)\n", numTS, reserved, length, plen)
	// selector region
	regionOff := off + 4
	regionLen := plen - 4
	if regionLen <= 0 {
		fmt.Printf("  No selectors present\n")
		return
	}
	fmt.Printf("  Selector region offset %d len %d\n", regionOff, regionLen)
	// Try deterministic parse
	ok := tryParseSelectors(b, regionOff, regionLen, true)
	if !ok && doResync {
		fmt.Println("  Deterministic parse failed or ambiguous; running exhaustive resync attempts...")
		candidates := resyncSelectors(b, regionOff, regionLen)
		if len(candidates) == 0 {
			fmt.Println("   No plausible selector parses found during resync.")
		} else {
			fmt.Printf("   Found %d plausible parse(s):\n", len(candidates))
			for i, seq := range candidates {
				fmt.Printf("   Candidate %d:\n", i+1)
				for j, s := range seq {
					matchTag := ""
					if s.IsIPv4 {
						ip := net.ParseIP(s.Src)
						if matchIP(ip) {
							matchTag = " [MATCH]"
						}
					}
					fmt.Printf("    sel[%d] offset=%d Type=0x%02X Proto=%d Len=%d", j, s.Off, s.Type, s.Proto, s.Len)
					if s.IsIPv4 {
						fmt.Printf(" IPv4 %s -> %s%s\n", s.Src, s.Dst, matchTag)
					} else if s.IsIPv4Ports {
						ip := net.ParseIP(s.Src)
						m := ""
						if matchIP(ip) {
							m = " [MATCH]"
						}
						fmt.Printf(" IPv4 Ports %d-%d %s -> %s%s\n", s.SPort, s.EPort, s.Src, s.Dst, m)
					} else if s.IsIPv6 {
						nip := net.ParseIP(s.Raw)
						m := ""
						if matchIP(nip) {
							m = " [MATCH]"
						}
						fmt.Printf(" IPv6 raw: 0x%s%s\n", s.Raw, m)
					} else {
						fmt.Printf(" raw: 0x%s\n", s.Raw)
					}
				}
			}
		}
	}
}

// selector struct for resync results
type Sel struct {
	Off         int
	Type        uint8
	Proto       uint8
	Len         int
	SPort, EPort uint16
	Src, Dst    string
	IsIPv4      bool
	IsIPv4Ports bool
	IsIPv6      bool
	Raw         string
}

// tryParseSelectors tries deterministic parse (expects standard lengths) and prints them; returns true if parse consumed region exactly with only recognized lengths.
func tryParseSelectors(b []byte, regionOff, regionLen int, print bool) bool {
	cursor := regionOff
	end := regionOff + regionLen
	selIndex := 0
	for cursor+4 <= end {
		tstype := b[cursor]
		proto := b[cursor+1]
		slen := int(be16(b, cursor+2))
		if slen < 4 || cursor+slen > end {
			if print {
				fmt.Printf("    selector[%d] @%d has invalid/truncated length %d (end %d)\n", selIndex, cursor, slen, end)
			}
			return false
		}
		bodyOff := cursor + 4
		switch slen {
		case 12:
			if bodyOff+8 <= len(b) {
				sa := be32(b, bodyOff)
				ea := be32(b, bodyOff+4)
				matchTag := ""
				if matchIP(ipFromUint32(sa)) || matchIP(ipFromUint32(ea)) {
					matchTag = " [MATCH]"
				}
				if print {
					fmt.Printf("    selector[%d] @%d: Type=0x%02X Proto=%d Len=%d IPv4: %s -> %s%s\n", selIndex, cursor, tstype, proto, slen, ipv4String(sa), ipv4String(ea), matchTag)
				}
			} else {
				if print {
					fmt.Printf("    selector[%d] truncated\n", selIndex)
				}
				return false
			}
		case 16:
			if bodyOff+12 <= len(b) {
				sp := be16(b, bodyOff)
				ep := be16(b, bodyOff+2)
				sa := be32(b, bodyOff+4)
				ea := be32(b, bodyOff+8)
				matchTag := ""
				if matchIP(ipFromUint32(sa)) || matchIP(ipFromUint32(ea)) {
					matchTag = " [MATCH]"
				}
				if print {
					fmt.Printf("    selector[%d] @%d: Type=0x%02X Proto=%d Len=%d IPv4 Ports: %d-%d Addr: %s -> %s%s\n", selIndex, cursor, tstype, proto, slen, sp, ep, ipv4String(sa), ipv4String(ea), matchTag)
				}
			} else {
				if print {
					fmt.Printf("    selector[%d] truncated\n", selIndex)
				}
				return false
			}
		case 28, 32:
			// heuristics for IPv6-ish lengths: print raw
			if print {
				fmt.Printf("    selector[%d] @%d: Type=0x%02X Proto=%d Len=%d IPv6-like raw: 0x%s\n", selIndex, cursor, tstype, proto, slen, hexSlice(b, bodyOff, slen-4))
			}
		default:
			if print {
				fmt.Printf("    selector[%d] @%d: Type=0x%02X Proto=%d Len=%d (unknown) raw: 0x%s\n", selIndex, cursor, tstype, proto, slen, hexSlice(b, bodyOff, slen-4))
			}
			// treat unknown length as parse failure for deterministic parse
			return false
		}
		cursor += slen
		selIndex++
	}
	if cursor != end {
		if print {
			fmt.Printf("    deterministic parse finished at %d but region end is %d (mismatch)\n", cursor, end)
		}
		return false
	}
	return true
}

// resyncSelectors tries every possible start offset inside region and returns candidate sequences that cover region exactly with per-selector recognized lengths
func resyncSelectors(b []byte, regionOff, regionLen int) [][]Sel {
	var results [][]Sel
	end := regionOff + regionLen
	// try starting offsets from regionOff to regionOff+3 (selector header alignment may be off)
	for start := regionOff; start < regionOff+4 && start < end; start++ {
		var seq []Sel
		cursor := start
		ok := true
		for cursor+4 <= end {
			tstype := b[cursor]
			proto := b[cursor+1]
			slen := int(be16(b, cursor+2))
			if slen < 4 || cursor+slen > end {
				ok = false
				break
			}
			bodyOff := cursor + 4
			s := Sel{Off: cursor, Type: tstype, Proto: proto, Len: slen}
			switch slen {
			case 12:
				s.IsIPv4 = true
				s.Src = ipv4String(be32(b, bodyOff))
				s.Dst = ipv4String(be32(b, bodyOff+4))
			case 16:
				s.IsIPv4Ports = true
				s.SPort = be16(b, bodyOff)
				s.EPort = be16(b, bodyOff+2)
				s.Src = ipv4String(be32(b, bodyOff+4))
				s.Dst = ipv4String(be32(b, bodyOff+8))
			case 28, 32:
				s.IsIPv6 = true
				s.Raw = hexSlice(b, bodyOff, slen-4)
			default:
				s.Raw = hexSlice(b, bodyOff, slen-4)
			}
			seq = append(seq, s)
			cursor += slen
		}
		if ok && cursor == end {
			results = append(results, seq)
		}
	}
	return results
}

// SA / Proposal / Transform parsing (best-effort)
func transformTypeName(ttype uint8) string {
	switch ttype {
	case 1:
		return "ENCR"
	case 2:
		return "PRF"
	case 3:
		return "INTEG"
	case 4:
		return "DH"
	default:
		return fmt.Sprintf("TYPE_0x%02X", ttype)
	}
}

func transformIDName(ttype uint8, tid uint16) string {
	switch ttype {
	case 1:
		if n, ok := encrNames[tid]; ok {
			return n
		}
	case 2:
		if n, ok := prfNames[tid]; ok {
			return n
		}
	case 3:
		if n, ok := integNames[tid]; ok {
			return n
		}
	case 4:
		if n, ok := dhNames[tid]; ok {
			return n
		}
	}
	return ""
}

func parseSA(b []byte, off, plen int) {
	if plen < 4 || off+4 > len(b) {
		fmt.Printf("  SA payload too short or truncated\n")
		return
	}
	fmt.Printf("  SA payload raw (%d bytes): 0x%s\n", plen, strings.ToUpper(hex.EncodeToString(b[off:off+plen])))
	// First 4 bytes often DOI (or similar)
	if plen >= 4 {
		fmt.Printf("    First 4 bytes (possibly DOI or proto-specific): 0x%08X\n", be32(b, off))
	}
	cursor := off
	end := off + plen
	// Try to parse proposals with heuristic: proposal header = 4 bytes: ProposalNum(1), ProtocolID(1), SPISize(1), NumTransforms(1)
	for cursor+4 <= end {
		propNum := b[cursor]
		protoID := b[cursor+1]
		spiSize := int(b[cursor+2])
		numTransforms := int(b[cursor+3])
		fmt.Printf("    Proposal @%d: Num=%d ProtocolID=%d SPI Size=%d NumTransforms=%d\n", cursor, propNum, protoID, spiSize, numTransforms)
		cursor += 4
		if cursor+spiSize > end {
			fmt.Printf("      Proposal SPI truncated (need %d bytes)\n", spiSize)
			return
		}
		if spiSize > 0 {
			fmt.Printf("      SPI: 0x%s\n", strings.ToUpper(hex.EncodeToString(b[cursor:cursor+spiSize])))
			cursor += spiSize
		}
		// Parse transforms
		for t := 0; t < numTransforms; t++ {
			if cursor+6 > end {
				fmt.Printf("      transform[%d] truncated header at %d\n", t, cursor)
				return
			}
			tlen := int(be16(b, cursor))
			ttype := b[cursor+2]
			// reserved := b[cursor+3]
			tid := be16(b, cursor+4)
			if tlen < 6 || cursor+tlen > end {
				fmt.Printf("      transform[%d] at %d has invalid length %d (needs >=6 and <=%d)\n", t, cursor, tlen, end-cursor)
				return
			}
			// Print with mapping
			ttName := transformTypeName(ttype)
			tidName := transformIDName(ttype, tid)
			if tidName != "" {
				fmt.Printf("      Transform[%d] @%d: Len=%d Type=%s(0x%02X) ID=0x%04X (%s)\n", t, cursor, tlen, ttName, ttype, tid, tidName)
			} else {
				fmt.Printf("      Transform[%d] @%d: Len=%d Type=%s(0x%02X) ID=0x%04X\n", t, cursor, tlen, ttName, ttype, tid)
			}
			attrOff := cursor + 6
			attrLen := tlen - 6
			if attrLen > 0 {
				attrs := b[attrOff : attrOff+attrLen]
				// Richer attribute decoding: attributes encoded as pairs where
				// first octet: AF (MSB) | AttrType (7 bits)
				// second octet: if AF==0 -> value (1 byte) (TV), if AF==1 -> length of value (L), and next L bytes are the value (TLV)
				// This heuristic matches common vendor encodings and lets us show type/value in readable form.
				i := 0
				for i+2 <= len(attrs) {
					at := attrs[i]
					av := attrs[i+1]
					af := at & 0x80
					typeNum := at & 0x7F
					if af == 0x00 {
						// TV: single-byte value
						fmt.Printf("        Attr TV: Type=%d Value=0x%02X (%d)\n", typeNum, av, av)
						i += 2
					} else {
						// TLV: av == length
						l := int(av)
						if i+2+l > len(attrs) {
							fmt.Printf("        Attr TLV truncated: Type=%d Len=%d (need %d bytes)\n", typeNum, l, l)
							break
						}
						val := attrs[i+2 : i+2+l]
						fmt.Printf("        Attr TLV: Type=%d Len=%d Value=0x%s\n", typeNum, l, strings.ToUpper(hex.EncodeToString(val)))
						i += 2 + l
					}
				}
				if i < len(attrs) {
					fmt.Printf("        Attr tail bytes: 0x%s\n", strings.ToUpper(hex.EncodeToString(attrs[i:])))
				}
			}
			cursor += tlen
		}
		// Continue to next proposal, if any
		}
	}

// Top-level payload walker
func parsePayloads(b []byte, start int, doResync bool) {
	cursor := start
	// If we had an IKE header, top-level next payload is at b[16]; otherwise use top-of-buffer
	var initialNP uint8
	if start == 28 && len(b) >= 17 {
		initialNP = b[16]
	} else {
		if len(b) >= 1 {
			initialNP = b[0]
		}
	}
	fmt.Printf("\nParsing payloads starting at offset %d (initial NextPayload=0x%02X %s)\n", cursor, initialNP, payloadName(initialNP))
	for cursor < len(b) {
		if cursor+4 > len(b) {
			fmt.Printf("Truncated: not enough bytes for payload header at %d\n", cursor)
			return
		}
		np := b[cursor]
		flags := b[cursor+1]
		plen := int(be16(b, cursor+2))
		if plen < 4 {
			fmt.Printf("Invalid payload length %d at %d\n", plen, cursor)
			return
		}
		if cursor+plen > len(b) {
			fmt.Printf("Payload at %d length %d extends past buffer (%d), clamping\n", cursor, plen, len(b))
			plen = len(b) - cursor
		}
		pt := np
		fmt.Printf("\nPayload @%d: Type/Next=0x%02X (%s) Flags=0x%02X Length=%d\n", cursor, pt, payloadName(pt), flags, plen)
		bodyOff := cursor + 4
		switch pt {
		case PT_NOTIFY:
			parseNotify(b, bodyOff, plen-4)
		case PT_AUTH:
			parseAuth(b, bodyOff, plen-4)
		case PT_TSi, PT_TSr:
			parseTS(b, bodyOff, plen-4, doResync)
		case PT_IDi, PT_IDr:
			parseID(b, bodyOff, plen-4)
		case PT_SA:
			parseSA(b, bodyOff, plen-4)
		case PT_SK:
			fmt.Printf("  SK (Encrypted) header seen. If this buffer is decrypted SK payload contents, inner payloads may follow here. Otherwise SK is encrypted and body contains IV+ciphertext.\n")
		default:
			fmt.Printf("  Raw payload (%d bytes): 0x%s\n", plen-4, strings.ToUpper(hex.EncodeToString(b[bodyOff:bodyOff+(plen-4)])))
		}
		cursor += plen
	}
}

func main() {
	resyncFlag := flag.Bool("resync", false, "run exhaustive TS resync attempts when TS payload parse ambiguous")
	matchFlag := flag.String("match", "", "comma-separated list of IPs or CIDRs to highlight (e.g. 10.0.0.1,192.168.0.0/16,2001:db8::/32)")
	flag.Parse()
	if flag.NArg() < 1 {
		fmt.Fprintf(os.Stderr, "Usage: %s [-resync] [-match ip1,net2,...] <hexstring>\n", os.Args[0])
		os.Exit(1)
	}
	// parse match list
	if *matchFlag != "" {
		parts := strings.Split(*matchFlag, ",")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			if strings.Contains(p, "/") {
				if _, netw, err := net.ParseCIDR(p); err == nil {
					matchCIDRs = append(matchCIDRs, netw)
				} else {
					fmt.Fprintf(os.Stderr, "warning: couldn't parse CIDR '%s': %v\n", p, err)
				}
			} else {
				ip := net.ParseIP(p)
				if ip != nil {
					matchIPs = append(matchIPs, ip)
				} else {
					fmt.Fprintf(os.Stderr, "warning: couldn't parse IP '%s'\n", p)
				}
			}
		}
	}

	in := strings.Join(flag.Args(), "")
	b := mustDecodeHex(in)
	start := 0
	if len(b) >= 28 {
		start = printIKEHeader(b)
	} else {
		fmt.Println("Parsing as raw payload bytes (no full IKE header found).")
	}
	parsePayloads(b, start, *resyncFlag)
}
