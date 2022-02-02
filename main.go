package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"github.com/miekg/dns"
	"golang.org/x/crypto/ssh"
)

type dnsSecHostKey struct {
	key     ssh.PublicKey
	message []string
}

func (d *dnsSecHostKey) check(hostAndPort string, remote net.Addr, key ssh.PublicKey) error {
	config := dns.ClientConfig{
		Servers: []string{
			"9.9.9.9",
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
		return err
	}
	if r.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("non-success response code: %d", r.Rcode)
	}

	keyBytes := key.Marshal()
	hasSSHFP := false
	for _, a := range r.Answer {
		if fp, ok := a.(*dns.SSHFP); ok {
			fingerprint, err := hex.DecodeString(fp.FingerPrint)
			if err != nil {
				return err
			}

			if fp.Algorithm > 3 && fp.Type > 1 {
				hasSSHFP = true
				fmt.Println(fp.Algorithm)
				switch fp.Type {
				case 2:
					hash := sha256.Sum256(keyBytes)
					if !bytes.Equal(fingerprint, hash[:]) {
						return fmt.Errorf("key mismatch for sha256")
					}
					return encryptData(key, strings.Join(d.message, " "))
					/*case 1:
					hash := sha1.Sum(keyBytes)
					if !bytes.Equal(fingerprint, hash[:]) {
						return fmt.Errorf("key mismatch for sha1")
					}
					*/
				}
			} else {
				continue
			}
		}
	}

	if hasSSHFP == false {
		return fmt.Errorf("no SSHFP record found for %q", hostname)
	}

	return nil
}

//DNSSECHostKey checks a hostkey against a DNSSEC SSHFP record
func DNSSECHostKey(message []string) ssh.HostKeyCallback {
	hk := &dnsSecHostKey{
		message: message,
	}
	return hk.check
}

func encryptData(pk ssh.PublicKey, data string) error {
	recipient, err := agessh.NewEd25519Recipient(pk)
	if err != nil {
		return fmt.Errorf("failed to parse public key %q: %v", pk, err)
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

func usage() {
	fmt.Println("dnage hostname 'message'")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	config := &ssh.ClientConfig{
		HostKeyCallback: DNSSECHostKey(os.Args[2:]),
		Timeout:         30 * time.Second,
	}

	_, err := ssh.Dial("tcp", os.Args[1], config)
	if err != nil {
		fmt.Println(err)
	}
}
