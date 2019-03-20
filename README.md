# cctrace

cctrace creates xplot.org plots of TCP congestion control signals including
CE, ECE, CWR and the proposed [SCE](https://github.com/dtaht/bufferbloat-rfcs/blob/master/sce/ELR%20Proposal%201%20(SCE).txt).

Feel free to report any problems or feature requests as issues. IPv6 is not
tested.

Install instructions:

1. Install libpcap
2. [Install Go](https://golang.org/dl/)
3. Install cctrace: `go install github.com/heistp/cctrace`
4. Run `cctrace` for usage
