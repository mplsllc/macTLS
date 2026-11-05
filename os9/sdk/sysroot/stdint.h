#ifndef _STDINT_H
#define _STDINT_H

/* Custom stdint.h for cross-compilation - includes stdint-gcc.h directly instead of using include_next */

#if __STDC_HOSTED__
# if defined __cplusplus && __cplusplus >= 201103L
#  undef __STDC_LIMIT_MACROS
#  define __STDC_LIMIT_MACROS
#  undef __STDC_CONSTANT_MACROS
#  define __STDC_CONSTANT_MACROS
# endif
# include "stdint-gcc.h"
#else
# include "stdint-gcc.h"
#endif

#endif /* _STDINT_H */
