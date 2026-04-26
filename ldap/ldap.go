package ldap // collector, wraps existing bloodhound types for seamless collection

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"

	"encoding/binary"
	"encoding/hex"
	CLI "github.com/Ceald1/gohound/cli"
	"github.com/TheManticoreProject/Manticore/network/kerberos"
	"github.com/charmbracelet/log"
	ldap "github.com/go-ldap/ldap/v3"
	gssapi "github.com/go-ldap/ldap/v3/gssapi"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
	"golang.org/x/crypto/md4"
	"unicode/utf16"
)

func CreateBaseDN(domain string) (result string) {
	domainSplit := strings.Split(domain, ".")
	prefixed := make([]string, len(domainSplit))
	for i, v := range domainSplit {
		prefixed[i] = "dc=" + v
	}
	result = strings.Join(prefixed, ",")
	return result
}

func DiscoverDC(domain string, dnsServer string) (string, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}

	_, addrs, err := resolver.LookupSRV(context.Background(), "ldap", "tcp", "dc._msdcs."+domain)
	if err != nil {
		return "", fmt.Errorf("failed to lookup LDAP SRV record: %v", err)
	}

	if len(addrs) == 0 {
		return "", fmt.Errorf("no LDAP servers found for domain %s", domain)
	}

	// Return the first server's target (remove trailing dot if present)
	target := strings.TrimSuffix(addrs[0].Target, ".")
	return target, nil
}

// create a new ldap client from cli results

func NewClient(results CLI.CLIResults) (l *ldap.Conn, err error) {
	ldaps := results.Ldaps
	kerb := results.Kerberos
	user := results.Username
	password := results.Password
	ntlm := strings.ToUpper(results.NtlmHash)
	dc := results.DC
	if dc == "" {
		dc = results.Domain
	}
	domain := results.Domain
	if domain == "" {
		return nil, errors.New("domain not specified")
	}

	address := fmt.Sprintf("%s:%s", dc, results.Port)

	if ldaps {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		l, err = ldap.DialTLS("tcp", address, tlsConfig)
	} else {
		l, err = ldap.Dial("tcp", address)
	}

	if err != nil {
		return nil, err
	}

	if kerb {
		dc, err = DiscoverDC(domain, dc)
		if err != nil {
			log.Warn(fmt.Sprintf("failed to discover DC.. %v", err))
		}
		spn, krb5Conf := kerberos.KerberosInit(dc, domain)
		realm := strings.ToUpper(domain)

		client := gssapi.Client{
			Client: krb5client.NewWithPassword(
				user,
				realm,
				password,
				krb5Conf,
				krb5client.DisablePAFXFAST(true),
			),
		}

		err = l.GSSAPIBindRequest(&client, &ldap.GSSAPIBindRequest{
			ServicePrincipalName: spn,
			AuthZID:              "",
		})
		if err == nil {
			return l, nil
		}

		log.Info("Falling back to ntlm auth..")
	}

	if password != "" {
		err = l.Bind(user, password)
	} else {
		err = l.NTLMBindWithHash(domain, user, ntlm)
	}

	return l, err
}

//func NewClient(results CLI.CLIResults) (l *ldap.Conn, err error) {
//	ldaps := results.Ldaps
//	protocol := "ldap://"
//	if ldaps {
//		protocol = "ldaps://"
//	}
//	kerb := results.Kerberos
//	user := results.Username
//	password := results.Password
//	ntlm := strings.ToUpper(results.NtlmHash)
//	dc := results.DC
//	if dc == "" {
//		dc = results.Domain
//	}
//	domain := results.Domain
//	if domain == "" {
//		err = errors.New("domain not specified")
//		return
//	}
//	ldapURL := fmt.Sprintf("%s%s:%s", protocol, dc, results.Port)
//	l, err = ldap.DialURL(ldapURL)
//	if err != nil {
//		return
//	}
//
//	if kerb {
//		dc, err = DiscoverDC(domain, dc)
//		if err != nil {
//			log.Warn(fmt.Sprintf("failed to discover DC.. %v", err))
//			//return nil, err
//		}
//		spn, krb5Conf := kerberos.KerberosInit(dc, domain)
//		realm := strings.ToUpper(domain)
//		client := gssapi.Client{
//			Client: krb5client.NewWithPassword(user, realm, password, krb5Conf, krb5client.DisablePAFXFAST(true)),
//		}
//		err = l.GSSAPIBindRequest(&client, &ldap.GSSAPIBindRequest{
//			ServicePrincipalName: spn,
//			AuthZID:              "",
//		})
//		if err == nil {
//			return
//		}
//		log.Info("Falling back to ntlm auth..")
//	}
//	if password != "" {
//		err = l.Bind(user, password)
//	} else {
//		err = l.NTLMBindWithHash(domain, user, ntlm)
//	}
//
//	return
//}

type ManagedPasswordBlob struct {
	Version                         uint16
	Reserved                        uint16
	Length                          uint32
	CurrentPasswordOffset           uint16
	PreviousPasswordOffset          uint16
	QueryPasswordIntervalOffset     uint16
	UnchangedPasswordIntervalOffset uint16

	CurrentPassword           []byte
	PreviousPassword          []byte
	QueryPasswordInterval     []byte
	UnchangedPasswordInterval []byte
}

func ParseManagedPasswordBlob(data []byte) (*ManagedPasswordBlob, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("blob too small")
	}

	b := &ManagedPasswordBlob{}

	// Header parsing (little endian)
	b.Version = binary.LittleEndian.Uint16(data[0:2])
	b.Reserved = binary.LittleEndian.Uint16(data[2:4])
	b.Length = binary.LittleEndian.Uint32(data[4:8])
	b.CurrentPasswordOffset = binary.LittleEndian.Uint16(data[8:10])
	b.PreviousPasswordOffset = binary.LittleEndian.Uint16(data[10:12])
	b.QueryPasswordIntervalOffset = binary.LittleEndian.Uint16(data[12:14])
	b.UnchangedPasswordIntervalOffset = binary.LittleEndian.Uint16(data[14:16])

	// ---- Current Password ----
	var endCurrent uint16
	if b.PreviousPasswordOffset == 0 {
		endCurrent = b.QueryPasswordIntervalOffset
	} else {
		endCurrent = b.PreviousPasswordOffset
	}

	b.CurrentPassword = data[b.CurrentPasswordOffset:endCurrent]

	// ---- Previous Password ----
	if b.PreviousPasswordOffset != 0 {
		b.PreviousPassword = data[b.PreviousPasswordOffset:b.QueryPasswordIntervalOffset]
	}

	// ---- Query Interval ----
	b.QueryPasswordInterval = data[b.QueryPasswordIntervalOffset:b.UnchangedPasswordIntervalOffset]

	// ---- Unchanged Interval ----
	b.UnchangedPasswordInterval = data[b.UnchangedPasswordIntervalOffset:]

	return b, nil
}

func StringToUTF16LE(s string) []byte {
	u16 := utf16.Encode([]rune(s))
	buf := make([]byte, len(u16)*2)

	for i, v := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], v)
	}

	return buf
}

func NTLMHash(password string) string {
	// Convert string → UTF-16LE bytes
	utf16Bytes := StringToUTF16LE(password)

	h := md4.New()
	h.Write(utf16Bytes)

	return hex.EncodeToString(h.Sum(nil))
}
