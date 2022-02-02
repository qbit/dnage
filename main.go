package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

var (
	port       string
	nameServer string
	nsProto    string
	message    string
)

type dnsSecHostKey struct {
	message string
}

func dnsSecErr(err error) {
	log.Fatalf("DNSSEC: %v\n", err)
}

func (d *dnsSecHostKey) check(hostAndPort string, remote net.Addr, key ssh.PublicKey) error {
	config := dns.ClientConfig{
		Servers: []string{
			nameServer,
		},
		Port: "53",
	}
	hostname := strings.Split(hostAndPort, ":")[0]
	c := dns.Client{
		Net: "tcp",
	}
	m := &dns.Msg{}
	m.SetEdns0(4096, true)

	m.SetQuestion(hostname+".", dns.TypeSSHFP)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, config.Servers[0]+":"+config.Port)
	if err != nil {
		dnsSecErr(err)
	}
	if r.Rcode != dns.RcodeSuccess {
		dnsSecErr(fmt.Errorf("non-success response code: %d", r.Rcode))
	}

	keyBytes := key.Marshal()
	hasSSHFP := false
	for _, a := range r.Answer {
		if fp, ok := a.(*dns.SSHFP); ok {
			fingerprint, err := hex.DecodeString(fp.FingerPrint)
			if err != nil {
				dnsSecErr(err)
			}

			// We only work with ed25519 keys.
			if fp.Algorithm == 4 && fp.Type == 2 {
				hasSSHFP = true
				hash := sha256.Sum256(keyBytes)
				if !bytes.Equal(fingerprint, hash[:]) {
					dnsSecErr(fmt.Errorf("key mismatch for %q", hostAndPort))
				}
				err := encryptData(key, d.message)
				if err != nil {
					log.Fatalln(fmt.Errorf("age: %w", err))
				}
			}
		}
	}

	if !hasSSHFP {
		dnsSecErr(fmt.Errorf("no SSHFP record found for %q", hostname))
	}

	return nil
}

//DNSSECHostKey checks a hostkey against a DNSSEC SSHFP record
func DNSSECHostKey(message string) ssh.HostKeyCallback {
	hk := &dnsSecHostKey{
		message: message,
	}
	return hk.check
}

func encryptData(pk ssh.PublicKey, data string) error {
	recipient, err := agessh.NewEd25519Recipient(pk)
	if err != nil {
		return err
	}

	buf := &bytes.Buffer{}
	armorWriter := armor.NewWriter(buf)

	w, err := age.Encrypt(armorWriter, recipient)
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}

	if err := armorWriter.Close(); err != nil {
		return err
	}

	fmt.Printf("%s", buf.Bytes())
	return nil
}

func main() {
	flag.StringVar(&port, "p", "22", "SSH port to connect to")
	flag.StringVar(&nameServer, "n", "9.9.9.9", "Name server to use, must support DNSSEC.")
	flag.StringVar(&nsProto, "np", "udp", "Protocol to query Name server with. Possibilities: tcp, tcp-tls, udp")
	flag.StringVar(&message, "m", "", "Message to encrypt")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] example.com\n\n", os.Args[0])
		flag.PrintDefaults()
		os.Exit(2)
	}
	flag.Parse()

	config := &ssh.ClientConfig{
		HostKeyAlgorithms: []string{"ssh-ed25519"},
		HostKeyCallback:   DNSSECHostKey(message),
	}

	// This will fail as we have no auth mechanisms
	_, _ = ssh.Dial("tcp", os.Args[len(os.Args)-1]+":"+port, config)
}
