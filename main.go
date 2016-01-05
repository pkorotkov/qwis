package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

const (
	version = "0.0.1"
)

var (
	lf     = []byte("\n")
	crlf   = []byte("\r\n")
	colon  = []byte(":")
	equals = []byte("=")
)

type WhoisResponse struct {
	DomainName     string   `json:"domain_name"`
	Registrar      string   `json:"registrar"`
	Statuses       []string `json:"statuses"`
	CreationDate   string   `json:"creation_date"`
	ExpirationDate string   `json:"expiration_date"`
}

func (wir *WhoisResponse) WriteAsJSON(w io.Writer) (err error) {
	wirj, err := json.Marshal(wir)
	if err != nil {
		return
	}
	var out bytes.Buffer
	json.Indent(&out, wirj, "", "    ")
	out.WriteTo(w)
	return
}

func topLevelDomain(domainName string) string {
	parts := strings.Split(domainName, ".")
	return parts[len(parts)-1]
}

func whoisServer(domainName string) string {
	return topLevelDomain(domainName) + ".whois-servers.net"
}

func getQuery(domainName string) []byte {
	q := []byte(domainName)
	switch topLevelDomain(domainName) {
	case "com":
		q = append(equals, q...)
	}
	return append(q, crlf...)
}

func isDomainName(l []byte) bool {
	return bytes.Equal(l, []byte("domain")) ||
		bytes.Equal(l, []byte("domain name"))
}

func isRegistrar(l []byte) bool {
	return bytes.Equal(l, []byte("registrar")) ||
		bytes.Equal(l, []byte("sponsoring registrar"))
}

func isStatus(l []byte) bool {
	return bytes.Equal(l, []byte("status")) ||
		bytes.Equal(l, []byte("domain status"))
}

func isCreationDate(l []byte) bool {
	return bytes.Contains(l, []byte("created")) ||
		bytes.Contains(l, []byte("creation"))
}

func isExperationDate(l []byte) bool {
	return bytes.Equal(l, []byte("expiry")) ||
		bytes.Contains(l, []byte("expiry date")) ||
		bytes.Equal(l, []byte("paid-till")) ||
		bytes.Contains(l, []byte("expiration"))
}

func buildResponse(rawWhoisResponse []byte) (*WhoisResponse, error) {
	r := &WhoisResponse{}
	rtlns := bytes.Split(rawWhoisResponse, lf)
	for _, rtln := range rtlns {
		sides := bytes.SplitN(rtln, colon, 2)
		if len(sides) == 1 {
			continue
		}
		lhs, rhs := bytes.ToLower(bytes.TrimSpace(sides[0])), string(bytes.TrimSpace(sides[1]))
		switch {
		case isDomainName(lhs):
			if len(r.DomainName) != 0 {
				return nil, fmt.Errorf("buildResponse: mutliple domain list is not accepted")
			}
			r.DomainName = rhs
		case isRegistrar(lhs):
			r.Registrar = rhs
		case isStatus(lhs):
			r.Statuses = append(r.Statuses, strings.TrimSpace(strings.Split(rhs, "http")[0]))
		case isCreationDate(lhs):
			r.CreationDate = rhs
		case isExperationDate(lhs):
			r.ExpirationDate = rhs
		}
	}
	return r, nil
}

func Whois(domainName string) (*WhoisResponse, error) {
	re := func(e error) error {
		return fmt.Errorf("Whois: %s", e)
	}
	conn, err := net.Dial("tcp", whoisServer(domainName)+":43")
	if err != nil {
		return nil, re(fmt.Errorf("failed to establish TCP connection with whois server"))
	}
	defer conn.Close()
	if _, err = conn.Write(getQuery(domainName)); err != nil {
		return nil, re(err)
	}
	var res []byte
	// TODO: Use sync.Pool.
	buf := make([]byte, 2048)
	for {
		numbytes, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			return nil, re(err)
		}
		res = append(res, buf[:numbytes]...)
		if err == io.EOF {
			break
		}
	}
	return buildResponse(res)
}

func printHelpMessage() {
	fmt.Fprintln(os.Stdout, "Quick whois utility")
	fmt.Fprintf(os.Stdout, "Version: %s\n", version)
	fmt.Fprintln(os.Stdout, "Usage:   qws [-r|-j] <-h>|<domain-name>")
	os.Exit(0)
}

func printErrorMessage(m string, ec int) {
	fmt.Fprintf(os.Stderr, "Error: %s\n", m)
	os.Exit(ec)
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		printHelpMessage()
	}
	var dn string
	switch args[0] {
	case "-h":
		printHelpMessage()
	case "-r":
		// TODO: Implement it.
		os.Exit(-1)
	case "-j":
		if len(args) == 2 {
			dn = args[1]
		} else {
			printErrorMessage("Invalid set of arguments", 1)
		}
	default:
		dn = args[0]
	}
	wir, err := Whois(dn)
	if err != nil {
		printErrorMessage(err.Error(), 2)
	}
	if err = wir.WriteAsJSON(os.Stdout); err != nil {
		printErrorMessage(err.Error(), 3)
	}
}
