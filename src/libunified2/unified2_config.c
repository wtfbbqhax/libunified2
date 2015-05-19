#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "unified2.h"

const char * unified2_lib_version( ) {
    const char * string = PACKAGE_VERSION;
    return string;
}

const char * unified2_lib_string( ) {
    const char * string = PACKAGE_STRING;
    return string;
}

const char * unified2_lib_bugreport( ) {
    const char * string = PACKAGE_BUGREPORT;
    return string;
}
