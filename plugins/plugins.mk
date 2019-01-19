#------------------------------------------------------------------------------
# loaders
#------------------------------------------------------------------------------

# raw
SRCS+=\
	plugins/loader_raw.d\

# bootsector
SRCS+=\
	plugins/loader_bootsector.d\

# elf
SRCS+=\
	plugins/loader_elf.d\

#------------------------------------------------------------------------------
# archictectures
#------------------------------------------------------------------------------

# arm
PKGS+=capstone
SRCS+=\
	plugins/arch_arm.d\
	bindings/capstone.d\

# jaguar
SRCS+=\
	plugins/arch_jaguar.d\

# nes
SRCS+=\
	plugins/arch_nes.d\

# x86
PKGS+=capstone
SRCS+=\
	plugins/arch_x86.d\
	bindings/capstone.d\

#------------------------------------------------------------------------------
# views
#------------------------------------------------------------------------------

# ncurses
PKGS+=ncurses
SRCS+=\
	plugins/view_console.d\
	bindings/ncurses.d\

# SDL
PKGS+=sdl2
SRCS+=\
	plugins/view_sdl.d\
	bindings/SDL.d\

# debug
SRCS+=\
	plugins/view_debug.d\

