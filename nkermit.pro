TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
    main.c \
    nkermit.c

HEADERS += \
    nkermit.h

LIBS += -lserialport

macos {
LIBS += -framework IOKit -framework CoreFoundation
}
