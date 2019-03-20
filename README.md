# cctrace

cctrace creates xplot.org plots of TCP congestion control signals including
CE, ECE, CWR and the proposed [SCE](https://github.com/dtaht/bufferbloat-rfcs/blob/master/sce/ELR%20Proposal%201%20(SCE).txt).

Feel free to report any problems or feature requests as issues. IPv6 is not
tested.

Install instructions:

1. Install libpcap
2. [Install Go](https://golang.org/dl/)
3. Install cctrace: `go get -u github.com/heistp/cctrace`
4. Make sure location of cctrace is in your `PATH` (by default `~/go/bin`)
5. Run `cctrace` for usage

Sample plot:

<img src="https://raw.githubusercontent.com/heistp/cctrace/master/sample_plot.png" width="968" height="617">
