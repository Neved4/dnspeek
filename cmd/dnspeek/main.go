package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	flag "github.com/spf13/pflag"

	core "dnspeek/internal"
)

const usageText = `usage: dnspeek -d <name> [-acfikpqsz] [-r <cidr|start-end>]
  [-t <type>] [-n <servers>] [-D <file>] [-T <num>] [-w <seconds>] [-C]

Flags (short, long, and -long aliases):
	-acfikpqsz	Bundle bools in sorted order.
	-d, -domain, --domain	Target domain (required for most scans).
	-r, -range	CIDR or start-end for reverse lookups.
	-t, -type	std|brt|srv|tld|rvl|axfr|cache|zonewalk.
	-n, -ns		Comma list of resolvers.
	-D, -dict	Wordlist for brute force.
	-T, -threads	Concurrency level.
	-p, -tcp	Force TCP.
	-f, -wildcard	Drop wildcard IPs during brute force.
	-i, -ignore	Continue brute force when wildcards exist.
	-s, -spf	Reverse SPF ranges during std scans.
	-z, -zone	Attempt DNSSEC NSEC walk during std scans.
	-q, -caa	Query CAA records during std scans.
	-c, -cache	Run cache snooping.
	-k, -crt	Scrape crt.sh during std scans.
	-a, -axfr	Try zone transfer in std scans.
	-w, -timeout	Per-query timeout in seconds.
	-C, -no-color	Disable ANSI colors.
`

func main() {
	cfg := core.Config{}

	var typeFlag string
	var nsFlag string

	registerFlags(&cfg, &typeFlag, &nsFlag)

	flag.Usage = func() {
		fmt.Print(usageText)
	}

	err := flag.CommandLine.Parse(
		normalizeArgs(os.Args[1:]),
	)
	if err != nil {
		os.Exit(2)
	}

	core.SetColor(!cfg.NoColor)
	cfg.ScanTypes = core.JoinAndTrim(typeFlag)
	cfg.Nameservers = core.JoinAndTrim(nsFlag)
	if len(cfg.ScanTypes) == 0 {
		cfg.ScanTypes = []string{"std"}
	}

	if err := core.ValidateFlags(cfg); err != nil {
		core.ErrLine(err.Error())
		os.Exit(1)
	}

	core.InfoLine("Starting dnspeek. Breathe easy, we got this.")
	if len(cfg.Nameservers) > 0 {
		core.DimLine(
			"Using custom nameservers: " + strings.Join(
				cfg.Nameservers,
				", ",
			),
		)
	}

	timeout := time.Duration(
		cfg.TimeoutSeconds * float64(time.Second),
	)
	res, err := core.NewResolver(
		cfg.Domain,
		cfg.Nameservers,
		cfg.UseTCP,
		timeout,
	)
	if err != nil {
		core.ErrLine(err.Error())
		os.Exit(1)
	}

	for _, t := range cfg.ScanTypes {
		switch t {
		case "std":
			if cfg.Domain == "" {
				core.ErrLine("std scan requires --domain")
				continue
			}
			_, err := core.GeneralEnum(
				res,
				cfg.Domain,
				cfg,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		case "brt":
			if cfg.Domain == "" {
				core.ErrLine("brt scan requires --domain")
				continue
			}
			_, err := core.BruteDomain(
				res,
				cfg.Dictionary,
				cfg.Domain,
				cfg.FilterWildcard,
				cfg.IgnoreWildcard,
				cfg.ThreadCount,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		case "srv":
			if cfg.Domain == "" {
				core.ErrLine("srv scan requires --domain")
				continue
			}
			_, err := core.BruteSrv(
				res,
				cfg.Domain,
				cfg.ThreadCount,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		case "tld":
			if cfg.Domain == "" {
				core.ErrLine("tld scan requires --domain")
				continue
			}
			_, err := core.BruteTLDs(
				res,
				cfg.Domain,
				cfg.ThreadCount,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		case "rvl":
			if cfg.RangeArg == "" {
				core.ErrLine("rvl scan requires --range")
				continue
			}
			ips, err := core.ParseRangeList(cfg.RangeArg)
			if err != nil {
				core.ErrLine(err.Error())
				continue
			}
			_, err = core.BruteReverse(
				res,
				ips,
				cfg.ThreadCount,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		case "axfr":
			if cfg.Domain == "" {
				core.ErrLine("axfr scan requires --domain")
				continue
			}
			local := cfg
			local.DoAXFR = true
			_, err := core.GeneralEnum(
				res,
				cfg.Domain,
				local,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		case "cache":
			if len(res.Nameservers()) == 0 {
				core.ErrLine("no nameservers available for cache snoop")
				continue
			}
			for _, ns := range res.Nameservers() {
				path := filepath.Join(
					core.EnvDataDir(),
					"snoop.txt",
				)
				_, err := core.CacheSnoop(
					ns,
					path,
					timeout,
				)
				if err != nil {
					core.ErrLine(err.Error())
				}
			}
		case "zonewalk":
			if cfg.Domain == "" {
				core.ErrLine("zonewalk requires --domain")
				continue
			}
			_, err := core.ZoneWalk(
				res,
				cfg.Domain,
				cfg.TimeoutSeconds,
			)
			if err != nil {
				core.ErrLine(err.Error())
			}
		default:
			core.WarnLine("unknown type: " + t)
		}
	}
}

func registerFlags(
	cfg *core.Config,
	typeFlag *string,
	nsFlag *string,
) {
	addString(
		"d", "domain", &cfg.Domain, "",
		"Target domain to enumerate.",
	)
	addString(
		"r", "range", &cfg.RangeArg, "",
		"IP range for reverse lookups (CIDR or start-end).",
	)
	addString(
		"D", "dict", &cfg.Dictionary, "namelist.txt",
		"Wordlist for brute force.",
	)
	addString(
		"t", "type", typeFlag, "std",
		"Scan types: std,brt,rvl,srv,tld,axfr,cache,zonewalk.",
	)
	addString(
		"n", "ns", nsFlag, "",
		"Comma list of nameservers to use.",
	)

	addBool(
		"p", "tcp", &cfg.UseTCP, false,
		"Force TCP for DNS queries.",
	)
	addBool(
		"f", "wildcard", &cfg.FilterWildcard, false,
		"Drop wildcard IPs during brute force.",
	)
	addBool(
		"i", "ignore", &cfg.IgnoreWildcard, false,
		"Keep brute forcing even when wildcards exist.",
	)
	addBool(
		"s", "spf", &cfg.DoSPF, false,
		"Reverse ranges seen in SPF during std scans.",
	)
	addBool(
		"z", "zone", &cfg.DoZoneWalk, false,
		"Attempt DNSSEC NSEC walk during std scans.",
	)
	addBool(
		"q", "caa", &cfg.DoCAA, false,
		"Query CAA records during std scans.",
	)
	addBool(
		"c", "cache", &cfg.DoCacheSnoop, false,
		"Check NS caches using test/snoop.txt.",
	)
	addBool(
		"k", "crt", &cfg.DoCRT, false,
		"Pull hostnames from crt.sh during std scans.",
	)
	addBool(
		"a", "axfr", &cfg.DoAXFR, false,
		"Try zone transfer as part of std scans.",
	)
	addBool(
		"C", "no-color", &cfg.NoColor, false,
		"Disable ANSI colors in output.",
	)

	addInt(
		"T", "threads", &cfg.ThreadCount, 20,
		"Concurrent lookups to perform.",
	)
	addFloat(
		"w", "timeout", &cfg.TimeoutSeconds, 5.0,
		"Per-query timeout in seconds.",
	)
}

func addString(
	shortName string,
	longName string,
	dest *string,
	def string,
	usage string,
) {
	flag.StringVarP(dest, longName, shortName, def, usage)
}

func addBool(
	shortName string,
	longName string,
	dest *bool,
	def bool,
	usage string,
) {
	flag.BoolVarP(dest, longName, shortName, def, usage)
}

func addInt(
	shortName string,
	longName string,
	dest *int,
	def int,
	usage string,
) {
	flag.IntVarP(dest, longName, shortName, def, usage)
}

func addFloat(
	shortName string,
	longName string,
	dest *float64,
	def float64,
	usage string,
) {
	flag.Float64VarP(dest, longName, shortName, def, usage)
}

var singleDashLong = map[string]struct{}{
	"domain":   {},
	"range":    {},
	"dict":     {},
	"type":     {},
	"ns":       {},
	"tcp":      {},
	"wildcard": {},
	"ignore":   {},
	"spf":      {},
	"zone":     {},
	"caa":      {},
	"cache":    {},
	"crt":      {},
	"axfr":     {},
	"threads":  {},
	"timeout":  {},
	"no-color": {},
}

func normalizeArgs(args []string) []string {
	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		if !strings.HasPrefix(arg, "-") ||
			strings.HasPrefix(arg, "--") ||
			arg == "-" {
			normalized = append(normalized, arg)
			continue
		}

		name := strings.TrimPrefix(arg, "-")
		value := ""
		if idx := strings.Index(name, "="); idx >= 0 {
			value = name[idx:]
			name = name[:idx]
		}

		if _, ok := singleDashLong[name]; ok {
			normalized = append(
				normalized,
				"--"+name+value,
			)
			continue
		}

		normalized = append(normalized, arg)
	}
	return normalized
}
