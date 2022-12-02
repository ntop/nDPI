// secure_memzero.h version 1 (October 29, 2016)
// 
// This code is released into the public domain.
//
// THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
// OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

// The secure_memzero macro/function attempts to ensure that an optimizing
// compiler does not remove the intended operation if cleared memory is not
// accessed again by the program. There are several known ways of doing this,
// however no single one is both universally available and absolutely guranteed
// by the standard. The following code defines secure_memzero as a macro or
// function using one of the known alternatives. The choice of implementation
// can be controlled by defining a preprocessor macro of the form SMZ_impl,
// where <impl> is one of the defined implementation names. SMZ_impl should
// expand to an integer indicating the dgeree of preference for the
// implementation, where numerically higher values indicate greater preference.
// Defining SMZ_impl to be 0 disables the implementation even if it is
// available. Not defining any SMZ_impl will result in default (safe) behavior.
// 
// The following implementations may be used.
// 
// SMZ_SECUREZEROMEMORY
// Uses the SecureZeroMemory macro/function on Windows. Requires a Windows
// environment (_WIN32 must be defined).
// 
// SMZ_ASM_BARRIER
// Uses a compiler memory barrier to force the results of a memset to be
// committed to memory. Has been tested to work on:
// - Clang 3.9.0 at all optimization levels.
// - GCC 6.2 at all optimization levels.
// 
// SMZ_MEMSET_S
// Uses the C11 function memset_s. Currently not available on many platforms.
// Note that if you want this option, you have to set __STDC_WANT_LIB_EXT1__
// to 1 before including string.h or any file that includes string.h in a
// compilation unit that includes this header.
// 
// SMZ_VDATAPTR
// Uses the volatile data pointer technique to zero one byte at a time. This is
// not guaranteed to work by the C standard, which does not require access to
// non-volatile objects via a pointer-to-volatile to be treated as a volatile
// access. However, it is known to work on the following compilers:
// - Clang 3.9.0 at all optimization levels.
// - GCC 6.2 at all optimization levels.
// 
// SMZ_VFUNCPTR
// Uses the volatile function pointer technique to call memset. This is not
// guaranteed to work by the C standard, which does not require the pointed-to
// function to be called. However, it is known to work on the following
// compilers:
// - Clang 3.9.0 at all optimization levels.
// - GCC 6.2 at all optimization levels.

// The remainder of this file implements the selection logic using the
// specified compile-time preferences.

#ifndef _SECURE_MEMZERO_H_
#define _SECURE_MEMZERO_H_

// STEP 1. Set default preference for all implementations to 1.

#ifndef SMZ_SECUREZEROMEMORY
#define SMZ_SECUREZEROMEMORY 1
#endif

#ifndef SMZ_MEMSET_S
#define SMZ_MEMSET_S 1
#endif

#ifndef SMZ_ASM_BARRIER
#define SMZ_ASM_BARRIER 1
#endif

#ifndef SMZ_VDATAPTR
#define SMZ_VDATAPTR 1
#endif

#ifndef SMZ_VFUNCPTR
#define SMZ_VFUNCPTR 1
#endif

// STEP 2. Check which implementations are available and include any necessary
// header files.

#if SMZ_SECUREZEROMEMORY > 0
#ifdef _WIN32
#include <windows.h>
#else
#undef SMZ_SECUREZEROMEMORY
#define SMZ_SECUREZEROMEMORY 0
#endif
#endif

#if SMZ_MEMSET_S > 0
#if defined(__STDC_WANT_LIB_EXT1__) && (__STDC_WANT_LIB_EXT1__ != 1)
#undef SMZ_MEMSET_S
#define SMZ_MEMSET_S 0
#endif
#if SMZ_MEMSET_S > 0
#ifndef __STDC_WANT_LIB_EXT1__
// Must come before first include of string.h
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#include <string.h>
#ifndef __STDC_LIB_EXT1__
#undef SMZ_MEMSET_S
#define SMZ_MEMSET_S 0
#endif
#endif
#endif

#if !defined(__GNUC__) && !defined(__clang__)
#undef SMZ_ASM_BARRIER
#define SMZ_ASM_BARRIER 0
#endif

#if SMZ_VFUNCPTR > 0
#include <string.h>
#endif

// STEP 3. Calculate highest preference.

#define SMZ_PREFERENCE 0

#if SMZ_PREFERENCE < SMZ_SECUREZEROMEMORY
#undef SMZ_PREFERENCE
#define SMZ_PREFERENCE SMZ_SECUREZEROMEMORY
#endif

#if SMZ_PREFERENCE < SMZ_MEMSET_S
#undef SMZ_PREFERENCE
#define SMZ_PREFERENCE SMZ_MEMSET_S
#endif

#if SMZ_PREFERENCE < SMZ_ASM_BARRIER
#undef SMZ_PREFERENCE
#define SMZ_PREFERENCE SMZ_ASM_BARRIER
#endif

#if SMZ_PREFERENCE < SMZ_VDATAPTR
#undef SMZ_PREFERENCE
#define SMZ_PREFERENCE SMZ_VDATAPTR
#endif

#if SMZ_PREFERENCE < SMZ_VFUNCPTR
#undef SMZ_PREFERENCE
#define SMZ_PREFERENCE SMZ_VFUNCPTR
#endif

// STEP 4. Make sure we have something chosen.

#if SMZ_PREFERENCE <= 0
#error No secure_memzero implementation available
#endif

// STEP 5. Use implementation with highest preference. Ties are broken in
// favor of implementations appearing first, below.

#if SMZ_PREFERENCE == SMZ_SECUREZEROMEMORY
#define secure_memzero(ptr,len) SecureZeroMemory((ptr),(len))

#elif SMZ_PREFERENCE == SMZ_MEMSET_S
#define secure_memzero(ptr,len) memset_s((ptr),(len),0,(len))

#elif SMZ_PREFERENCE == SMZ_ASM_BARRIER
#define secure_memzero(ptr,len) do { \
	memset((ptr),0,(len)); \
	__asm__ __volatile__("" ::"r"(ptr): "memory"); \
} while (0)

#elif SMZ_PREFERENCE == SMZ_VDATAPTR
static void secure_memzero(void * ptr, size_t len) {
	volatile char * p = ptr;
	while (len--) *p++ = 0;
}

#elif SMZ_PREFERENCE == SMZ_VFUNCPTR
static void * (* volatile _smz_memset_fptr)(void*,int,size_t) = &memset;
static void secure_memzero(void * ptr, size_t len) {
	_smz_memset_fptr(ptr, 0, len);
}

#endif

#endif // _SECURE_MEMZERO_H_
