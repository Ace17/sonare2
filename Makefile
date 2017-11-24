BIN?=bin

DC?=gdc

DFLAGS+=-funittest
DFLAGS+=-Ibindings

SRCS:=\
	core/main.d\
	core/arch.d\
	core/assertion.d\
	core/debugger.d\
	core/disassemble.d\
	core/document.d\
	core/input_sink.d\
	core/loader.d\
	core/shell.d\
	core/presenter.d\
	core/registry.d\
	core/view.d\

include plugins/plugins.mk

$(BIN)/snr: $(SRCS)
	@mkdir -p $(dir $@)
	$(DC) $^ $(DFLAGS) $(LDFLAGS) -o "$@"

#------------------------------------------------------------------------------
# Generic rules
#------------------------------------------------------------------------------
CXXFLAGS+=$(shell pkg-config $(PKGS) --cflags)
LDFLAGS+=$(shell pkg-config $(PKGS) --libs)

clean:
	rm -rf $(BIN)

