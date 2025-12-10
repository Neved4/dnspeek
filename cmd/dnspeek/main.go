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

	flag.StringVarP(
		&cfg.Domain,
		"domain",
		"d",
		"",
		"Target domain to enumerate.",
	)
	flag.StringVarP(
		&cfg.RangeArg,
		"range",
		"r",
		"",
		"IP range for reverse lookups (CIDR or start-end).",
	)
	flag.StringVarP(
		&cfg.Dictionary,
		"dict",
		"D",
		"namelist.txt",
		"Wordlist for brute force.",
	)
	flag.StringVarP(
		&typeFlag,
		"type",
		"t",
		"std",
		"Scan types: std,brt,rvl,srv,tld,axfr,cache,zonewalk.",
	)
	flag.StringVarP(
		&nsFlag,
		"ns",
		"n",
		"",
		"Comma list of nameservers to use.",
	)

	flag.BoolVarP(
		&cfg.UseTCP,
		"tcp",
		"p",
		false,
		"Force TCP for DNS queries.",
	)
	flag.BoolVarP(
		&cfg.FilterWildcard,
		"wildcard",
		"f",
		false,
		"Drop wildcard IPs during brute force.",
	)
	flag.BoolVarP(
		&cfg.IgnoreWildcard,
		"ignore",
		"i",
		false,
		"Keep brute forcing even when wildcards exist.",
	)
	flag.BoolVarP(
		&cfg.DoSPF,
		"spf",
		"s",
		false,
		"Reverse ranges seen in SPF during std scans.",
	)
	flag.BoolVarP(
		&cfg.DoZoneWalk,
		"zone",
		"z",
		false,
		"Attempt DNSSEC NSEC walk during std scans.",
	)
	flag.BoolVarP(
		&cfg.DoCAA,
		"caa",
		"q",
		false,
		"Query CAA records during std scans.",
	)
	flag.BoolVarP(
		&cfg.DoCacheSnoop,
		"cache",
		"c",
		false,
		"Check NS caches using test/snoop.txt.",
	)
	flag.BoolVarP(
		&cfg.DoCRT,
		"crt",
		"k",
		false,
		"Pull hostnames from crt.sh during std scans.",
	)
	flag.BoolVarP(
		&cfg.DoAXFR,
		"axfr",
		"a",
		false,
		"Try zone transfer as part of std scans.",
	)
	flag.BoolVarP(
		&cfg.NoColor,
		"no-color",
		"C",
		false,
		"Disable ANSI colors in output.",
	)

	flag.IntVarP(
		&cfg.ThreadCount,
		"threads",
		"T",
		20,
		"Concurrent lookups to perform.",
	)
	flag.Float64VarP(
		&cfg.TimeoutSeconds,
		"timeout",
		"w",
		5.0,
		"Per-query timeout in seconds.",
	)

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
