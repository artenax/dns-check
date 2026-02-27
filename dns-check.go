package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/netutil/sysresolv"
	"github.com/miekg/dns"
)

type dnsResponse struct {
	Response bool
	Zero     bool
	Answer   []dnsAnswer
}

type dnsAnswer struct {
	A    string
	AAAA string
}

type dnsResponseHTTPS struct {
	Answer []dnsAnswerHTTPS
}

type dnsAnswerHTTPS struct {
	Value []interface{}
}

// type dnsValueHTTPS struct {
// 	Alpn []string
// 	ECH  string
// }

type whoisRecord struct {
	Handle   string
	Country  string
	Name     string
	Type     string
	Events   []whoisEvents
	Entities []whoisEntities
}

type whoisEvents struct {
	EventAction string
	EventDate   string
}

type whoisEntities struct {
	Handle     string
	VCardArray []interface{}
}

var (
	VERSION     = "1.3"
	PROGRAMNAME = "Resolve And Whois"
	AUTHOR      = "Ori"

	_resolver      = "system"
	_ipv           = 4
	_timeout       = 2
	_timeoutWhois  = 4
	_skipVerify    = true
	_addrToResolve = "example.com"
	_ArgPrefix     = "+"

	// https://rdap-bootstrap.arin.net/bootstrap/ip/
	// https://rdap.arin.net/registry/ip/
	_registry = "https://rdap.arin.net/registry/ip/"
)

func init() {
	log.SetFlags(0)
	log.Println()
	switch len(os.Args) {
	case 1:
		showHelp()
	case 2:
		if string(os.Args[1]) == "?" || string(os.Args[1]) == "-?" || string(os.Args[1]) == "-h" || string(os.Args[1]) == "-help" || string(os.Args[1]) == "--help" {
			showHelp()
		} else {
			_addrToResolve = extractDomain(os.Args[1])
		}
	case 3:
		handleArgs()
	case 4:
		handleArgs()
	default:
		showHelp()
	}
}

func main() {
	if _resolver == "system" {
		systemResolvers, err := sysresolv.NewSystemResolvers(nil, 53)
		if err != nil {
			check(fmt.Errorf("can't get system resolvers: %v", err))
		}
		_resolver = systemResolvers.Addrs()[0].String()
		log.Printf("DNS:\t%s (system)\n\n", _resolver)
	} else {
		log.Printf("DNS:\t%s\n\n", _resolver)
	}

	log.Printf("URL:\t%s\n", _addrToResolve)
	_reply, err := dnsLookup()
	if err != nil {
		check(fmt.Errorf("can't finish DNS lookup: %v", err))
	}
	if !_reply.Response || _reply.Zero {
		check(fmt.Errorf("response from DNS doesn't contain IP"))
	}
	_ip := returnSingularIP(_reply)
	if _ip == "" {
		check(fmt.Errorf("no IP found"))
	}
	log.Printf("IP:\t%s\n", _ip)

	_replyHTTPS, err := dnsLookupHTTPS()
	if err != nil {
		check(fmt.Errorf("can't finish DNS lookup with HTTPS RRTYPE: %v", err))
	}
	_alpn := false
	_ech := false
	if _replyHTTPS.Answer != nil {
		for _, item := range _replyHTTPS.Answer[0].Value {
			if keyValue, ok := item.(map[string]interface{}); ok {
				for key, value := range keyValue {
					if key == "Alpn" {
						log.Printf("HTTPv:\t%s\n", value)
						_alpn = true
					}
					if key == "ECH" {
						log.Printf("ECH:\tYES\n")
						_ech = true
					}
				}
			}
		}
	}
	if !_alpn {
		log.Printf("HTTPv:\tnot specified\n")
	}
	if !_ech {
		log.Printf("ECH:\tNO\n")
	}
	log.Println()

	_who, _whoSource, err := doWhois(_ip)
	if err != nil {
		check(fmt.Errorf("can't finish whois request: %v", err))
	}
	log.Printf("Whois record source: %s\n\n", _whoSource)

	if _who.Handle != "" {
		log.Printf("Handle:\t\t%s\n", _who.Handle)
	}
	if _who.Name != "" {
		log.Printf("Name:\t\t%s\n", _who.Name)
	}
	if _who.Type != "" {
		log.Printf("Net Type:\t%s\n", _who.Type)
	}
	if _who.Country != "" {
		log.Printf("Country:\t%s\n", _who.Country)
	}
	for _, event := range _who.Events {
		if event.EventAction == "registration" {
			t := parseTime(event.EventDate)
			log.Printf("Registration:\t%s\n", t)
			break
		}
	}
	for i := 0; i < len(_who.Entities); i++ {
		log.Printf("Entity %d:\n", i)
		if _who.Entities[i].Handle != "" {
			log.Printf("\tHandle:\t\t%s\n", _who.Entities[i].Handle)
		}
		if nestedArray, ok := _who.Entities[i].VCardArray[1].([]interface{}); ok {
			for _, item := range nestedArray {
				if keyValue, ok := item.([]interface{}); ok && len(keyValue) >= 4 && keyValue[0] == "fn" && keyValue[3] != "" {
					log.Printf("\tFull Name:\t%s\n", keyValue[3])
				}
				if keyValue, ok := item.([]interface{}); ok && len(keyValue) >= 4 && keyValue[0] == "org" && keyValue[3] != "" {
					log.Printf("\tOrganization:\t%s\n", keyValue[3])
				}
			}
		}
	}
	os.Exit(0)
}

func parseTime(t string) string {
	tt, err := time.Parse("2006-01-02T15:04:05Z", t)
	if err == nil {
		tt = tt.Local()
		t = tt.Format("_2 Jan 2006 15:04:05 MST")
		return t
	}
	t = t[:19]
	tt, err = time.Parse("2006-01-02T15:04:05", t)
	if err == nil {
		tt = tt.Local()
		t := tt.Format("_2 Jan 2006 15:04:05 MST")
		return t
	}
	return t
}

func handleArgs() {
	for i := 1; i < len(os.Args); i++ {
		if string(os.Args[i][0]) == _ArgPrefix && len(os.Args[i]) > 1 {
			if string(os.Args[i]) == "+4" || string(os.Args[i]) == "+6" {
				_ipv = int(os.Args[i][1] - '0')
			} else {
				_resolver = cleanDnsURL(os.Args[i])
			}
		} else {
			_addrToResolve = extractDomain(os.Args[i])
		}
	}
}

func showHelp() {
	log.Printf("\t%s v%s by %s\n\n", PROGRAMNAME, VERSION, AUTHOR)
	log.Printf("\tUSAGE: PROGRAMNAME +<IPv> +<RESOLVER> <ADDRESS TO RESOLVE>\n")
	log.Printf("\tEXAMPLE 1: %s +6 +dns.google example.com\n", filepath.Base(os.Args[0]))
	log.Printf("\tEXAMPLE 2: %s +8.8.8.8:53 https://example.com/\n", filepath.Base(os.Args[0]))
	os.Exit(0)
}

func extractDomain(url string) string {
	u := strings.ToLower(url)
	replacer := strings.NewReplacer("http://", "", "https://", "")
	u = replacer.Replace(u)
	u = strings.Split(u, `/`)[0]
	return u
}

func cleanDnsURL(url string) string {
	u := strings.TrimLeft(url, _ArgPrefix)
	u = strings.ToLower(u)

	if u == "system" {
		return u
	}

	replacer := strings.NewReplacer("http://", "", "https://", "")
	u = replacer.Replace(u)

	uu := strings.Split(u, `/`)

	isIP := strings.Split(uu[0], `:`)
	if len(isIP) > 1 {
		return uu[0]
	}

	if len(uu) == 1 {
		return "https://" + uu[0] + "/dns-query"
	} else {
		return "https://" + u
	}
}

func dnsLookup() (dnsResponse, error) {
	var c dnsResponse

	o := &upstream.Options{
		Timeout:            time.Duration(_timeout) * time.Second,
		InsecureSkipVerify: _skipVerify,
		HTTPVersions:       []upstream.HTTPVersion{upstream.HTTPVersion2, upstream.HTTPVersion11},
	}

	u, err := upstream.AddressToUpstream(_resolver, o)
	if err != nil {
		return c, fmt.Errorf("can't create an upstream: %v", err)
	}
	defer u.Close()

	var q = dns.Question{
		Name:   dns.Fqdn(_addrToResolve),
		Qclass: dns.ClassINET,
	}

	switch _ipv {
	case 4:
		q.Qtype = dns.TypeA
	case 6:
		q.Qtype = dns.TypeAAAA
	}

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{q}

	resp, err := u.Exchange(req)
	if err != nil {
		return c, fmt.Errorf("can't resolve '%s': %v", _addrToResolve, err)
	}

	var b []byte
	b, err = json.Marshal(resp)
	if err != nil {
		return c, fmt.Errorf("can't marshal json: %v", err)
	}
	//log.Println("reply:", string(b))

	err = json.Unmarshal(b, &c)
	if err != nil {
		return c, fmt.Errorf("can't unmarshal json: %v", err)
	}

	return c, nil
}

func dnsLookupHTTPS() (dnsResponseHTTPS, error) {
	var c dnsResponseHTTPS

	o := &upstream.Options{
		Timeout:            time.Duration(_timeout) * time.Second,
		InsecureSkipVerify: _skipVerify,
		HTTPVersions:       []upstream.HTTPVersion{upstream.HTTPVersion2, upstream.HTTPVersion11},
	}

	u, err := upstream.AddressToUpstream(_resolver, o)
	if err != nil {
		return c, fmt.Errorf("can't create an upstream: %v", err)
	}
	defer u.Close()

	var q = dns.Question{
		Name:   dns.Fqdn(_addrToResolve),
		Qclass: dns.ClassINET,
		Qtype:  dns.TypeHTTPS,
	}

	req := &dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{q}

	resp, err := u.Exchange(req)
	if err != nil {
		return c, fmt.Errorf("can't resolve '%s': %v", _addrToResolve, err)
	}

	var b []byte
	b, err = json.Marshal(resp)
	if err != nil {
		return c, fmt.Errorf("can't marshal json: %v", err)
	}
	//log.Println("reply https:", string(b))

	err = json.Unmarshal(b, &c)
	if err != nil {
		return c, fmt.Errorf("can't unmarshal json: %v", err)
	}

	return c, nil
}

func returnSingularIP(_resp dnsResponse) (_ip string) {
	for _, a := range _resp.Answer {
		switch _ipv {
		case 4:
			if a.A != "" {
				return a.A
			}
		case 6:
			if a.AAAA != "" {
				return a.AAAA
			}
		}
	}
	return ""
}

func doWhois(_ip string) (whoisRecord, string, error) {
	var w whoisRecord

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{
		InsecureSkipVerify: _skipVerify,
	}
	http.DefaultClient.Timeout = time.Duration(_timeoutWhois) * time.Second

	resp, err := http.Get(_registry + _ip)
	if err != nil {
		return w, "", fmt.Errorf("can't get proper response from whois: %v", err)
	}
	defer resp.Body.Close()

	bytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return w, "", fmt.Errorf("can't read response body: %v", err)
	}
	if len(bytes) == 0 {
		return w, "", fmt.Errorf("response body is empty")
	}

	err = json.Unmarshal(bytes, &w)
	if err != nil {
		return w, "", fmt.Errorf("can't unmarshal json: %v", err)
	}

	return w, extractDomain(resp.Request.URL.String()), nil
}

func check(err error) {
	switch err {
	case nil:
		return
	default:
		log.Println("Critical error:", err)
		os.Exit(1)
	}
}

