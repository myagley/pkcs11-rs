#define CK_PTR *

#define CK_DECLARE_FUNCTION(returnType, name) \
	returnType name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
	returnType (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
	returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11-2.40/pkcs11.h"
