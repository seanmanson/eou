#	$OpenBSD: Makefile,v 1.21 2014/11/20 08:50:53 bentley Exp $
#	@(#)Makefile.in	8.75 (Berkeley) 10/23/96

PROG=	vi

# Modern curses (ncurses)
CFLAGS+=-I${.CURDIR} -I${.CURDIR}/../include
LDADD+=-lcurses
DPADD+= ${LIBCURSES}

LDADD+=-lutil
DPADD+= ${LIBUTIL}

# incorrect code in vs_msg()
.if ${MACHINE_ARCH} == "sh"
CFLAGS+= -fno-tree-dominator-opts
.endif

SRCS=	cl_funcs.c cl_main.c cl_read.c cl_screen.c cl_term.c \
	cut.c delete.c ex.c ex_abbrev.c ex_append.c ex_args.c ex_argv.c \
	ex_at.c ex_bang.c ex_cd.c ex_cmd.c ex_cscope.c ex_delete.c \
	ex_display.c ex_edit.c ex_equal.c ex_file.c ex_filter.c \
	ex_global.c ex_init.c ex_join.c ex_map.c ex_mark.c ex_mkexrc.c \
	ex_move.c ex_open.c ex_preserve.c ex_print.c ex_put.c \
	ex_quit.c ex_read.c ex_screen.c ex_script.c ex_set.c ex_shell.c \
	ex_shift.c ex_source.c ex_stop.c ex_subst.c ex_tag.c \
	ex_txt.c ex_undo.c ex_usage.c ex_util.c ex_version.c ex_visual.c \
	ex_write.c ex_yank.c ex_z.c exf.c getc.c key.c line.c log.c main.c \
	mark.c msg.c options.c options_f.c put.c recover.c screen.c \
	search.c seq.c util.c v_at.c v_ch.c v_cmd.c v_delete.c v_ex.c \
	v_increment.c v_init.c v_itxt.c v_left.c v_mark.c v_match.c \
	v_paragraph.c v_put.c v_redraw.c v_replace.c v_right.c v_screen.c \
	v_scroll.c v_search.c v_section.c v_sentence.c v_status.c v_txt.c \
	v_ulcase.c v_undo.c v_util.c v_word.c v_xchar.c v_yank.c v_z.c \
	v_zexit.c vi.c vs_line.c vs_msg.c vs_refresh.c vs_relative.c \
	vs_smap.c vs_split.c

LINKS=	${BINDIR}/vi ${BINDIR}/ex
LINKS+=	${BINDIR}/vi ${BINDIR}/view
MLINKS=	vi.1 ex.1
MLINKS+=	vi.1 view.1

.PATH: ${.CURDIR}/../vi ${.CURDIR}/../ex ${.CURDIR}/../cl ${.CURDIR}/../common ${.CURDIR}/../docs/USD.doc/vi.man

.include "../../Makefile.inc"
.include <bsd.prog.mk>

CATALOGS=	dutch english french german polish ru_RU.KOI8-R spanish \
		swedish uk_UA.KOI8-U
afterinstall:
	${INSTALL} -d ${DESTDIR}${SHAREDIR}/vi/catalog
	(cd ${.CURDIR}/../catalog && ${INSTALL} -m ${NONBINMODE} -c ${CATALOGS} ${DESTDIR}/usr/share/vi/catalog )
	${INSTALL} -m ${BINMODE} -o ${BINOWN} -g ${BINGRP} -c ${.CURDIR}/recover ${DESTDIR}/usr/libexec/vi.recover
