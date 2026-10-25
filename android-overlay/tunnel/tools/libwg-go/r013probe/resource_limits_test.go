// SPDX-License-Identifier: MIT
package awgprobe

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

func TestProbeResourceBudgetRejectsUnboundedInputBeforeUDP(t *testing.T) {
	r, _ := fixture(t)
	for name, extra := range map[string]string{
		"junk_uint32":       "jc=4294967295\n",
		"junk_negative":     "jc=-1\n",
		"junk_reversed":     "jmin=100\njmax=10\n",
		"junk_large_size":   "jmax=4294967295\n",
		"padding_large":     "s1=4294967295\n",
		"random_negative":   "i1=<r -1>\n",
		"random_large":      "i1=<r 2147483647>\n",
		"chars_negative":    "i1=<rc -1>\n",
		"digits_large":      "i1=<rd 99999999>\n",
		"datasize_negative": "i1=<dz -5>\n",
		"sum_exceeds":       "i1=<r 4096><t>\n",
		"unknown_tag":       "i1=<future 1>\n",
		"unclosed_tag":      "i1=<r 10\n",
		"malformed_hex":     "i1=<b 0xzz>\n",
		"large_config":      "i1=" + strings.Repeat("a", 65536) + "\n",
		"many_lines":        strings.Repeat("replace_peers=false\n", 1025),
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakePhysicalFactory{}
			b, _ := NewPhysicalBind(netip.MustParseAddrPort("127.0.0.1:12345"), f)
			request := r
			request.Bind = b
			request.Config += extra
			if _, err := Measure(context.Background(), request); !errors.Is(err, ErrProbeBudget) {
				t.Fatal("unbounded input admitted", err)
			}
			if f.opens != 0 {
				t.Fatal("unsafe profile opened a UDP session")
			}
		})
	}
	for _, spec := range []string{"<r 64><b 0x0102><t><d><ds><dz 2>", "<rc 40><rd 30>", "<b 00>"} {
		if err := validateProbeResources(r.Config + "i1=" + spec + "\n"); err != nil {
			t.Fatal("ordinary AWG initial packet rejected", err)
		}
	}
}
