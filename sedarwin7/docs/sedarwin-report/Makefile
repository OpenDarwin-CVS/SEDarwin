all: sedarwin.ps sedarwin.pdf

sedarwin.pdf: sedarwin.dvi
	dvipdf sedarwin.dvi

sedarwin.ps: sedarwin.dvi
	dvips -o sedarwin.ps sedarwin.dvi

sedarwin.dvi: sedarwin.tex intro.tex framework.tex api.tex mach.tex \
	      sebsd.tex bsd.tex test.tex sedarwin.bib future.tex
	latex sedarwin.tex
	bibtex sedarwin
	latex sedarwin.tex
	latex sedarwin.tex
	latex sedarwin.tex

clean:
	rm -f sedarwin.log sedarwin.dvi sedarwin.blg sedarwin.bbl \
	      sedarwin.aux sedarwin.ps sedarwin.pdf sedarwin.toc
