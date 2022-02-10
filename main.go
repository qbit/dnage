package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"filippo.io/age"
	"filippo.io/age/agessh"
	"filippo.io/age/armor"
	"golang.org/x/crypto/ssh"
	"suah.dev/hostkeydns"
)

var (
	port       string
	nameServer string
	nsProto    string
	message    string
)

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
		HostKeyCallback: hostkeydns.CheckDNSSecHostKey(hostkeydns.DNSSecResolvers{
			Servers: []string{nameServer},
			Port:    "53",
			Net:     nsProto,
			Success: func(key ssh.PublicKey) {
				err := encryptData(key, message)
				if err != nil {
					log.Fatal(err)
				}
			},
		}),
	}

	// This will fail as we have no auth mechanisms
	_, _ = ssh.Dial("tcp", os.Args[len(os.Args)-1]+":"+port, config)
}
