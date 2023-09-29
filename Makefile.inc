# Should be included from other Makefiles.

#MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# 0 == debug off, anything else switches DEBUG on
DEBUG ?= 1
PROFILE ?= 0
STATIC ?= 0
STATICLIBS ?= 0

TOPDIR ?= $(PWD)

# Figure out PKGNAME - override from elsewhere if possible.
PKGDIRNAME = $(lastword $(subst /, ,$(shell readlink -f $(TOPDIR))))
PKGNAME ?= $(shell echo "$(PKGDIRNAME)" | sed -re 's/(-[0-9]+)*$$//')
PKGVERSION ?= $(shell echo "$(PKGDIRNAME)" | sed -nre 's/^([^-]|-[0-9]*[^0-9-])+-([0-9]+(-[0-9]+)?)$$/\2/p')
MODNAME ?= $(filter-out $(PKGNAME),$(lastword $(subst /, ,$(CURDIR))))

# This is a C++ based lib.  End of story.
CC := g++
AR := ar
MVN=mvn
JAVAC ?= ${JAVA_HOME}/bin/javac
RANLIB ?= ranlib
ECHO_E ?= /bin/echo -e   # Don't just use echo: in dash it doesn't process -e

CFLAGS ?= -W -Wall
LDFLAGS ?=

CFLAGS += -Iinclude
LDFLAGS += -rdynamic -Llib

LATEX_OPTS += -output-directory $(dir $@) -halt-on-error

OPTIM ?= -O2

ifneq ($(shell [ -r pom.xml ] && echo 1),)
JAVA_BASE=src/main/java
else
JAVA_BASE=src
endif

ifneq ($(JNI_CLASSES),)
EXTRA_MODULE_DIRS+=$(JAVA_HOME)
EXTRA_CFLAGS+=-I$(JAVA_HOME)/include/linux
JNI_HEADERS := $(patsubst %,include/%.h,$(subst .,_,$(JNI_CLASSES)))
JNI_SOURCES=$(foreach H,$(JNI_HEADERS),$(JAVA_BASE)/$(subst _,/,$(basename $(notdir $(H)))).java)
endif

ifneq ($(EXTRA_MODULE_DIRS),)
CFLAGS += $(foreach D,$(EXTRA_MODULE_DIRS),-I$(D)/include)
LDFLAGS += $(foreach D,$(EXTRA_MODULE_DIRS),-L$(D)/lib)
endif

ifneq ($(EXTRA_FLAGS),)
CFLAGS += $(EXTRA_FLAGS)
LDFLAGS += $(EXTRA_FLAGS)
endif
ifneq ($(EXTRA_CFLAGS),)
CFLAGS += $(EXTRA_CFLAGS)
endif
ifneq ($(EXTRA_LDFLAGS),)
LDFLAGS += $(EXTRA_LDFLAGS)
endif

CFLAGS += $(OPTIM)
CFLAGS += $(DEFS)

ifeq (${TARGET_LIB},)
RPATHDIR ?= $(EXTRA_RPATHDIR)
else
RPATHDIR ?= $(EXTRA_RPATHDIR) $(PWD)/lib
endif

INCDIRS := $(shell [ -d include ] && find include -type d | sed -e 's:^include::')

NODECS ?=
LATEX ?= latex
DVIPS ?= dvips
DVIPDF ?= dvipdf
GIT ?= git

PREFIX ?= /usr
BINDIR ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
LIBDIR ?= $(PREFIX)/lib
INCDIR ?= $(PREFIX)/include
SHAREDIR ?= $(PREFIX)/share/$(PKGNAME)
MODDIR ?= $(SHAREDIR)$(if $(MODNAME),/$(MODNAME),)
ETCDIR ?= $(PREFIX)/etc

DESTDIR ?= /

# Naming as per tex(1).
export TEXINPUTS=tex:$(TOPDIR)/tex:tex-tmp:
export DVIPSHEADERS=doc:$(TOPDIR)/tex:

-include $(TOPDIR)/Makefile.extra

##############################################################################################
#### From here on there should be no reason to change unless you know what you are doing. ####
##############################################################################################
.PHONY: default
default: all

LIB_TARGET_SO := $(foreach L,$(TARGET_LIBS),lib/lib$(L).so)
ifneq ($(STATICLIBS),0)
LIB_TARGET_A := $(foreach L,$(TARGET_LIBS),lib/lib$(L).a)
endif
BIN_TARGET := $(foreach B,$(TARGET_BINS),bin/$(B))
MOD_TARGET := $(foreach M,$(TARGET_MODS),modules/$(M).so)
JAR_TARGET := $(foreach J,$(TARGET_JARS),jar/$(J).jar)

ifeq ($(NODOCS),)
DOC_PDF := $(foreach D,$(TARGET_DOCS),doc/$(D).pdf)
DOC_PS := $(foreach D,$(TARGET_DOCS),doc/$(D).ps)
endif

ALL_TARGET :=
ALL_TARGET += $(LIB_TARGET_SO)
ALL_TARGET += $(LIB_TARGET_A)
ALL_TARGET += $(BIN_TARGET)
ALL_TARGET += $(MOD_TARGET)
ALL_TARGET += $(JAR_TARGET)
ALL_TARGET += $(DOC_PDF)
ALL_TARGET += $(EXTRA_ALL_TARGET)

BINMODS := $(foreach B,$(TARGET_BINS),$(MODS_$(B)))
LIBMODS := $(foreach L,$(TARGET_LIBS),$(MODS_$(L)))
MODMODS := $(foreach M,$(TARGET_MODS),$M)
ALLMODS := $(BINMODS) $(LIBMODS) $(MODMODS)

$(LIBMODS:%=obj/%.o) $(MODMODS:%=obj/%.o): CFLAGS += -fpic

.PHONY: all
all: $(ALL_TARGET)
	@echo "Everything has been brought up to date"

.PHONY: docs pdfdoc psdoc
psdoc : $(DOC_PS)
pdfdoc : $(DOC_PDF)
docs : psdoc pdfdoc

.PHONY: mvn
mvn:
	@[ ! -r pom.xml ] || $(MVN) compile

# Delete targets if/when updating them fails.
.DELETE_ON_ERROR:

# some systems require -fpic on .so files.
ifeq ($(shell uname -m),x86_64)
$(patsubst %,obj/%.o,$(foreach L,$(TARGET_LIBS),$(MODS_$(L)))) : CFLAGS += -fpic
endif

ifneq ($(DEBUG),0)
DEFS += -DDEBUG
CFLAGS += -g -ggdb
LDFLAGS += -g -ggdb
OPTIM = -O0
else
DEFS += -DNDEBUG
OPTIM = -O2
endif

ifneq ($(PROFILE),0)
CFLAGS += -pg
LDFLAGS += -pg
endif

ifneq ($(STATIC),0)
$(BIN_TARGET) : LDFLAGS += -static
endif

ifneq ($(OPTIM),)
CFLAGS += $(OPTIM)
endif

ifneq ($(RPATHDIR),)
LDFLAGS += $(foreach RD,$(RPATHDIR),-Wl,-rpath,$(shell readlink -f "$(RD)"))
endif

ifneq ($(VERBOSE),)
SHOWCL=
TEXMODE=nonstopmode
else
SHOWCL=@
TEXMODE=batchmode
endif

LDFLAGS_mysqlclient = $(shell mysql_config --libs)
LDFLAGS_mysqlclient_r = $(shell mysql_config --libs_r)

##########################################
# Custom functions that we can use for performing some tasks.
#
define format_lib
$(if $(LDFLAGS_$1),$(LDFLAGS_$1),-l$1)
endef

define uls_pkgconfig
$(shell
if which $(1)_config >/dev/null; then
	$(1)_config --$(2);
elif pkg-config --exists $(1); then
	pkg-config $(1) --$(2);
else
	echo "Error locating pkg-config for $(1)" >&2;
	/bin/false;
fi)
endef

define uls_libs
$(foreach L,$(LIBS) $(LIBS_$(1)),$(call format_lib,$(L))) \
	$(foreach P,$(PKG) $(PKG_$(1)),$(call uls_pkgconfig,$(P),libs))
endef

##########################################
# How to build actual binaries/libraries
#
$(LIB_TARGET_SO): | lib/.d
	@$(ECHO_E) "\t[LD - SO] $@"
	$(SHOWCL)$(CC) $(LDFLAGS) -shared -o $@ $(foreach M,$(MODS_$(patsubst lib/lib%.so,%,$@)),obj/$(M).o) $(call uls_libs,$(patsubst lib/lib%.so,%,$@))

$(LIB_TARGET_A): | lib/.d
	@$(ECHO_E) "\t[AR] $@"
	$(SHOWCL)$(AR) cru $@ $(foreach M,$(MODS_$(patsubst lib/lib%.a,%,$@)),obj/$(M).o)
	$(SHOWCL)$(RANLIB) $@

$(MOD_TARGET): | modules/.d
	@$(ECHO_E) "\t[LD - MOD] $@"
	$(SHOWCL)$(CC) $(LDFLAGS) -shared -o $@ $(@:modules/%.so=obj/%.o) $(call uls_libs,$(patsubst modules/%.so,%,$@))
	
$(BIN_TARGET): | bin/.d
	@$(ECHO_E) "\t[LD] $@"
	$(SHOWCL)$(CC) $(LDFLAGS) -o $@ $(foreach M,$(MODS_$(notdir $(basename $@))),obj/$(M).o) -Wl,--as-needed $(call uls_libs,$(patsubst bin/%,%,$@))

$(JAR_TARGET): | jar/.d
	@$(ECHO_E) "\t[JAR] $@"
	$(SHOWCL)jar c$(if $(JARMAIN_$(notdir $(basename $@))),e,)f $(JARMAIN_$(notdir $(basename $@))) $@ -C class $(foreach C,$(JAR_$(notdir $(basename $@))),$(subst .,/,$(C)).class)

##########################################
# Pattern matched build targets.
#

obj/%.o : src/%.c Makefile
	@$(ECHO_E) "\t[CC] $@"
	$(SHOWCL)$(CC) -x c $(CFLAGS) -o $@ -c $<

obj/%.o : src/%.C Makefile
	@$(ECHO_E) "\t[CXX] $@"
	$(SHOWCL)$(CC) $(CFLAGS) -o $@ -c $<

deps/%.d : src/%.c Makefile | deps/.d
	@$(ECHO_E) "\t[DEP] $@"
	$(SHOWCL)$(CC) -x c $(CFLAGS) -o $@ -MT "$@ obj/$*.o" -MM $<

deps/%.d : src/%.C Makefile | deps/.d
	@$(ECHO_E) "\t[DEP] $@"
	$(SHOWCL)$(CC) $(CFLAGS) -o $@ -MT "$@ obj/$*.o" -MM $<

deps/TEX_%.td : tex/%.tex | deps/.d
	@$(ECHO_E) "\t[TEXIDEP] $@"
	$(SHOWCL)>$@
	$(SHOWCL)echo "TEXDEPS_$*=$<" >> $@
	$(SHOWCL)sed -nre 's:.*\\usepackage\{([^}]*)\}:\1:p' < $< | sort -u | while read PKGNAME; do [ -r "$${PKGNAME}.sty" ] && echo "TEXDEPS_$*+=$${PKGNAME}.sty"; done >> $@ || /bin/true
	$(SHOWCL)sed -nre 's:.*\\(input|include)\{(([^.}]|\.[^t}]|\.t[^e}]|\.te[^x}])+)(\.tex)?}.*:\2:p' < $< | sort -u | sed -e 's:.*:-include deps/TEX_\0.td\nTEXDEPS_$*+=$$(TEXDEPS_\0):' >> $@
	$(SHOWCL)sed -nre 's:.*\\includegraphics([[][^]]*[]])?\{([^}]*)\}.*:\2:p' < $< | sort -u | sed -e 's:.*:TEX_IMG_$*+=tex/\0:' >> $@
	$(SHOWCL)sed -nre 's:.*\\epsfig\{file=([^,}]+)[,}].*:\1:p' < $< | sort -u | sed -e 's:.*:TEX_IMG_$*+=tex/\0:' >> $@
	$(SHOWCL)echo 'TEXDEPS_$*+=$$(TEX_IMG_$*)' >> $@
	$(SHOWCL)echo 'TEXIMAGES+=$$(TEX_IMG_$*)' >> $@

deps/%.td : | tex/%.tex deps/.d
	@$(ECHO_E) "\t[TEXDEP] $@"
	$(SHOWCL)>$@
	$(SHOWCL)echo "-include deps/TEX_$*.td" >>$@
	$(SHOWCL)echo 'tex-tmp/$*.dvi : $$(TEXDEPS_$*)' >>$@

# Java is somewhat trickier.  We can generate everything in one go assuming
# JNI_HEADERS's classes comes from a subject of JAVA_CLASSES, but as per usual,
# nothing is quite that simple, even though the assumption will usually hold.
# Just end up compiling twice and be done with it.
ifneq ($(JNI_HEADERS),)
$(JNI_HEADERS) &: include/.d
	@$(ECHO_E) "\t[JAVAH] $(JNI_HEADERS)"
	$(SHOWCL)td=$$(mktemp -d); $(JAVAC) -d "$${td}" -h include/ $(JNI_SOURCES); ex=$$?; rm -rf "$${td}"; exit $$ex
endif

JAVA_CLASSES = $(subst .,/,$(sort $(foreach J,$(TARGET_JARS),$(JAR_$(J)))))
JAVA_CLASSFILES = $(patsubst %,class/%.class,$(JAVA_CLASSES))
JAVA_SOURCEFILES = $(patsubst %,$(JAVA_BASE)/%.java,$(JAVA_CLASSES))

ifneq ($(JAVA_CLASSFILES),)
class/%.class : src/%.java Makefile
$(JAVA_CLASSFILES) &: | class/.d
	@$(ECHO_E) "\t[JAVAC] $(JAVA_CLASSES)"
	$(SHOWCL)$(JAVAC) -d class/ $(JAVA_SOURCEFILES)
endif

$.eps : %.dia
	@$(ECHO_E) "\t[DIA] $<"
	$(SHOWCL)dia --export $@ $<

%.eps : %.jpg
	@$(ECHO_E) "\t[EPS] $<"
	$(SHOWCL)convert $< $@

%.eps : %.png
	@$(ECHO_E) "\t[EPS] $<"
	$(SHOWCL)convert $< $@

.PRECIOUS: tex-tmp/%.log
tex-tmp/%.dvi tex-tmp/%.aux tex-tmp/%.log tex-tmp/%.toc : tex/%.tex | tex-tmp/.d
	$(ECHO_E) "\t[TEX] $@"
	$(SHOWCL)outp=$$($(LATEX) $(LATEX_OPTS) $< </dev/null) || (echo "$${outp}" && /bin/false)
	$(SHOWCL)outp=$$($(LATEX) $(LATEX_OPTS) $< </dev/null) || (echo "$${outp}" && /bin/false)
	$(SHOWCL)outp=$$($(LATEX) $(LATEX_OPTS) $< </dev/null) || (echo "$${outp}" && /bin/false)

#	$(SHOWCL)$(LATEX) -output-directory $(dir $@) -interaction $(TEXMODE) -halt-on-error $<
#	$(SHOWCL)$(LATEX) -output-directory $(dir $@) -interaction $(TEXMODE) -halt-on-error $<

#doc/%.pdf : tex-tmp/%.dvi | doc/.d
#	@$(ECHO_E) "\t[PDF] $@"
#	$(SHOWCL)$(DVIPDF) $< $@

doc/%.ps : tex-tmp/%.dvi | doc/.d
	@$(ECHO_E) "\t[PS] $@"
	$(SHOWCL)outp=$$($(DVIPS) -o $@ $< 2>&1) || (echo "$${outp}" && /bin/false)

doc/%.pdf : doc/%.ps
	@$(ECHO_E) "\t[PDF] $@"
	$(SHOWCL)$(PS2PDF) $< $@

.PRECIOUS: tex/%_log.tex
tex/%_log.tex : tex/%.tex
	@$(ECHO_E) "\t[TEXLOG] $<"
	$(SHOWCL)echo '\begin{itemize}' >$@
	$(SHOWCL)$(GIT) log --format=format:"\\item %ad (%an): %s" $< >>$@
	$(SHOWCL)echo '\end{itemize}' >>$@

.PRECIOUS: %/.d
%/.d :
	@$(ECHO_E) "\t[DIR] $(dir $@)"
	$(SHOWCL)mkdir -p $(dir $@)
	@touch $@

#include/ui_%.h : ui/%.ui
#	uic $< -o $@
#
#src/moc_%.C : include/%.h
#	moc $< -o $@
#
#src/ui_%.C : ui/%.ui
#	uic -impl ui_$*.h $< -o $@

##########################################
# Dependancy files.  For example, we need a way to tell make
# that objects needs to be brough up to date before the binaries.
#
depfiles := deps/Makefile
deps/Makefile : Makefile | deps/.d
	@$(ECHO_E) "\t[DEP] $@"
	$(SHOWCL)>$@
	$(SHOWCL)$(foreach B,$(TARGET_BINS),echo "bin/$(B) : $(patsubst %,obj/%.o,$(MODS_$(B)))" >> $@;)
	$(SHOWCL)$(foreach L,$(TARGET_LIBS),echo "lib/lib$(L).so lib/lib$(L).a : $(patsubst %,obj/%.o,$(MODS_$(L)))" >> $@;)
	$(SHOWCL)$(foreach M,$(TARGET_MODS),echo "modules/$(M).so : obj/$(M).o" >> $@;)
	$(SHOWCL)$(if $(filter $(LIBS),$(TARGET_LIBS)),echo "$(strip $(LIB_TARGET_SO) $(BIN_TARGET)) : $(foreach L,$(filter $(LIBS),$(TARGET_LIBS)),lib/lib$(L).so lib/lib$(L).a)" >> $@;,)
	$(SHOWCL)$(foreach B,$(TARGET_BINS),$(if $(filter $(LIBS_$(B)),$(TARGET_LIBS)),echo "bin/$(B) : $(foreach L,$(filter $(LIBS_$(B)),$(TARGET_LIBS)),lib/lib$(L).so lib/lib$(L).a)" >> $@;,))
	$(SHOWCL)$(foreach L,$(TARGET_LIBS),$(if $(filter $(LIBS_$(L)),$(TARGET_LIBS)),echo "lib/lib$(L).so : $(foreach L,$(filter $(LIBS_$(L)),$(TARGET_LIBS)),lib/lib$(L).so)" >> $@;,))
	$(SHOWCL)$(foreach M,$(ALLMODS),echo "obj/$(M).o : | $(dir obj/$(M)).d" >>$@;)
	$(SHOWCL)$(foreach B,$(TARGET_BINS),$(if $(PKG_$(B)),echo bin/$(B) : CFLAGS += $(foreach P,$(PKG_$(B)),$(call uls_pkgconfig,$(P),cflags)) >>$@;))
	$(SHOWCL)$(foreach L,$(TARGET_LIBS),$(if $(PKG_$(L)),echo lib/lib$(L).so lib/lib$(L).a : CFLAGS += $(foreach P,$(PKG_$(L)),$(call uls_pkgconfig,$(P),cflags)) >>$@;))
	$(SHOWCL)$(foreach M,$(TARGET_MODS),$(if $(PKG_$(M)),echo modules/$(M).so : CFLAGS += $(foreach P,$(PKG_$(M)),$(call uls_pkgconfig,$(P),cflags)) >>$@;))
	$(SHOWCL)$(foreach J,$(TARGET_JARS),echo "jar/$(J).jar : $(patsubst %,class/%.class,$(subst .,/,$(JAR_$(J))))" >> $@;)

depfiles += $(patsubst %,deps/%.d,$(ALLMODS))
ifneq ($(JNI_HEADERS),)
$(patsubst %,deps/%.d,$(ALLMODS)) : $(JNI_HEADERS)
endif
ifeq ($(NODOCS),)
depfiles += $(patsubst %,deps/%.td,$(TARGET_DOCS))
endif

deps/.d : $(filter-out deps/.d,$(addsuffix .d,$(dir $(depfiles))))

.PHONY: clean
clean :
	@$(ECHO_E) "\t[RM] deps/"
	$(SHOWCL)rm -rf deps
	@$(ECHO_E) "\t[RM] obj/"
	$(SHOWCL)rm -rf obj
	@$(ECHO_E) "\t[RM] include/ui_*.h"
	$(SHOWCL)rm -f include/ui_*.h
	@$(ECHO_E) "\t[RM] src/mod_*.C"
	$(SHOWCL)rm -f src/moc_*.C
	@$(ECHO_E) "\t[RM] src/ui_*.C"
	$(SHOWCL)rm -f src/ui_*.C
	@$(ECHO_E) "\t[RM] ui/*~"
	$(SHOWCL)rm -f ui/*~
	@$(ECHO_E) "\t[RM] tex-tmp/"
	$(SHOWCL)rm -rf tex-tmp
	@$(ECHO_E) "\t[RM] class/"
	$(SHOWCL)rm -rf class
ifneq ($(TEXIMAGES),)
	# Unfortunately this doesn't work because it relies on the depfiles...
	@$(ECHO_E) "\t[RM] $(TEXIMAGES)"
	$(SHOWCL)rm -f $(TEXIMAGES)
endif
ifneq ($(JNI_CLASSES),)
	@$(ECHO_E) "\t[RM] $(JNI_HEADERS)"
	$(SHOWCL)rm -f $(JNI_HEADERS)
endif
ifneq ($(EXTRA_CLEAN),)
	@$(ECHO_E) "\t[RM] $(EXTRA_CLEAN)"
	$(SHOWCL)rm -rf $(EXTRA_CLEAN)
endif

.PHONY: distclean
distclean : clean
ifneq ($(BIN_TARGET),)
	@$(ECHO_E) "\t[RM] $(BIN_TARGET)"
	$(SHOWCL)rm -f $(BIN_TARGET)
endif
ifneq ($(DOC_PS),)
	@$(ECHO_E) "\t[RM] $(DOC_PS)"
	$(SHOWCL)rm -f $(DOC_PS)
endif
ifneq ($(JAR_TARGET),)
	@$(ECHO_E) "\t[RM] $(JAR_TARGET)"
	$(SHOWCL)rm -f $(JAR_TARGET)
endif
ifneq ($(DOC_PDF),)
	@$(ECHO_E) "\t[RM] $(DOC_PDF)"
	$(SHOWCL)rm -f $(DOC_PDF)
endif
	@$(ECHO_E) "\t[RM] lib/"
	$(SHOWCL)rm -rf lib
	@$(ECHO_E) "\t[RM] modules/"
	$(SHOWCL)rm -rf modules

.PHONY: install
install : all
	@echo "Preparing to install into $(DESTDIR)."
ifneq ($(BIN_TARGET)$(EXTRA_BINS),)
	@$(ECHO_E) "\t[DIR] $(BINDIR)"
	$(SHOWCL)install -d "$(DESTDIR)$(BINDIR)"
endif
ifneq ($(BIN_TARGET),)
	$(SHOWCL)$(foreach B,$(BIN_TARGET),$(ECHO_E) "\t[BIN] $(B)"; install $(B) "$(DESTDIR)$(BINDIR)";)
endif
ifneq ($(EXTRA_BINS),)
	$(SHOWCL)$(foreach B,$(EXTRA_BINS),$(ECHO_E) "\t[BIN] $(B)"; install bin/$(B) "$(DESTDIR)$(BINDIR)";)
endif
ifneq ($(LIB_TARGET_SO),)
	@$(ECHO_E) "\t[DIR] $(LIBDIR)"
	$(SHOWCL)install -d "$(DESTDIR)$(LIBDIR)"
	$(SHOWCL)$(foreach L,$(LIB_TARGET_SO),$(ECHO_E) "\t[LIB] $(L)"; install "$(L)" "$(DESTDIR)$(LIBDIR)";)
	$(SHOWCL)$(foreach L,$(LIB_TARGET_A),$(ECHO_E) "\t[LIB] $(L)"; install -m0644 "$(L)" "$(DESTDIR)$(LIBDIR)";)
endif
ifneq ($(INCDIRS),)
	$(SHOWCL)$(foreach D,$(INCDIRS),$(ECHO_E) "\t[DIR] $(INCDIR)$(D)"; install -d "$(DESTDIR)$(INCDIR)$(D)"; $(foreach F,$(shell find "include$(D)" -maxdepth 1 -type f),$(ECHO_E) "\t[INC] $(F)"; install -m0644 "$(F)" "$(DESTDIR)$(INCDIR)$(D)";))
endif
ifneq ($(MOD_TARGET),)
	@$(ECHO_E) "\t[DIR] $(MODDIR)"
	$(SHOWCL)install -d "$(DESTDIR)$(MODDIR)"
	$(SHOWCL)$(foreach M,$(MOD_TARGET),$(ECHO_E) "\t[MOD] $(M)"; install $(M) "$(DESTDIR)$(MODDIR)";)
endif
	@echo "All installed."

##########################################
# This whole thing is to determine whether we need the depfiles or not.
#
NODEP_TARGETS += clean distclean
depinc := 1
ifneq (,$(filter $(NODEP_TARGETS),$(MAKECMDGOALS)))
depinc := 0
endif
ifneq (,$(filter-out $(NODEP_TARGETS),$(MAKECMDGOALS)))
depinc := 1
endif

ifeq ($(depinc),1)
-include $(depfiles)
endif
