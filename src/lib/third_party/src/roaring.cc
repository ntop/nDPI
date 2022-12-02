// !!! DO NOT EDIT - THIS IS AN AUTO-GENERATED FILE !!!
// Created by amalgamation.sh on Mer 25 Ago 2021 04:24:41 CEST

/*
 * Copyright 2016-2020 The CRoaring authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "roaring.h"

/* used for http://dmalloc.com/ Dmalloc - Debug Malloc Library */
#ifdef DMALLOC
#include "dmalloc.h"
#endif

#include "roaring.h"  /* include public API definitions */
/* begin file include/roaring/isadetection.h */
/* From
https://github.com/endorno/pytorch/blob/master/torch/lib/TH/generic/simd/simd.h
Highly modified.

Copyright (c) 2016-     Facebook, Inc            (Adam Paszke)
Copyright (c) 2014-     Facebook, Inc            (Soumith Chintala)
Copyright (c) 2011-2014 Idiap Research Institute (Ronan Collobert)
Copyright (c) 2012-2014 Deepmind Technologies    (Koray Kavukcuoglu)
Copyright (c) 2011-2012 NEC Laboratories America (Koray Kavukcuoglu)
Copyright (c) 2011-2013 NYU                      (Clement Farabet)
Copyright (c) 2006-2010 NEC Laboratories America (Ronan Collobert, Leon Bottou,
Iain Melvin, Jason Weston) Copyright (c) 2006      Idiap Research Institute
(Samy Bengio) Copyright (c) 2001-2004 Idiap Research Institute (Ronan Collobert,
Samy Bengio, Johnny Mariethoz)

All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

3. Neither the names of Facebook, Deepmind Technologies, NYU, NEC Laboratories
America and IDIAP Research Institute nor the names of its contributors may be
   used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef ROARING_ISADETECTION_H
#define ROARING_ISADETECTION_H

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(HAVE_GCC_GET_CPUID) && defined(USE_GCC_GET_CPUID)
#include <cpuid.h>
#endif // defined(_MSC_VER)


enum croaring_instruction_set {
  CROARING_DEFAULT = 0x0,
  CROARING_NEON = 0x1,
  CROARING_AVX2 = 0x4,
  CROARING_SSE42 = 0x8,
  CROARING_PCLMULQDQ = 0x10,
  CROARING_BMI1 = 0x20,
  CROARING_BMI2 = 0x40,
  CROARING_ALTIVEC = 0x80,
  CROARING_UNINITIALIZED = 0x8000
};

#if defined(__PPC64__)

static inline uint32_t dynamic_croaring_detect_supported_architectures() {
  return CROARING_ALTIVEC;
}

#elif defined(__arm__) || defined(__aarch64__) // incl. armel, armhf, arm64

#if defined(__ARM_NEON)

static inline uint32_t dynamic_croaring_detect_supported_architectures() {
  return CROARING_NEON;
}

#else // ARM without NEON

static inline uint32_t dynamic_croaring_detect_supported_architectures() {
  return CROARING_DEFAULT;
}

#endif

#elif defined(__x86_64__) || defined(_M_AMD64) // x64




static inline void cpuid(uint32_t *eax, uint32_t *ebx, uint32_t *ecx,
                         uint32_t *edx) {

#if defined(_MSC_VER)
  int cpu_info[4];
  __cpuid(cpu_info, *eax);
  *eax = cpu_info[0];
  *ebx = cpu_info[1];
  *ecx = cpu_info[2];
  *edx = cpu_info[3];
#elif defined(HAVE_GCC_GET_CPUID) && defined(USE_GCC_GET_CPUID)
  uint32_t level = *eax;
  __get_cpuid(level, eax, ebx, ecx, edx);
#else
  uint32_t a = *eax, b, c = *ecx, d;
  __asm__("cpuid\n\t" : "+a"(a), "=b"(b), "+c"(c), "=d"(d));
  *eax = a;
  *ebx = b;
  *ecx = c;
  *edx = d;
#endif
}

static inline uint32_t dynamic_croaring_detect_supported_architectures() {
  uint32_t eax, ebx, ecx, edx;
  uint32_t host_isa = 0x0;
  // Can be found on Intel ISA Reference for CPUID
  static uint32_t cpuid_avx2_bit = 1 << 5;      ///< @private Bit 5 of EBX for EAX=0x7
  static uint32_t cpuid_bmi1_bit = 1 << 3;      ///< @private bit 3 of EBX for EAX=0x7
  static uint32_t cpuid_bmi2_bit = 1 << 8;      ///< @private bit 8 of EBX for EAX=0x7
  static uint32_t cpuid_sse42_bit = 1 << 20;    ///< @private bit 20 of ECX for EAX=0x1
  static uint32_t cpuid_pclmulqdq_bit = 1 << 1; ///< @private bit  1 of ECX for EAX=0x1
  // ECX for EAX=0x7
  eax = 0x7;
  ecx = 0x0;
  cpuid(&eax, &ebx, &ecx, &edx);
  if (ebx & cpuid_avx2_bit) {
    host_isa |= CROARING_AVX2;
  }
  if (ebx & cpuid_bmi1_bit) {
    host_isa |= CROARING_BMI1;
  }

  if (ebx & cpuid_bmi2_bit) {
    host_isa |= CROARING_BMI2;
  }

  // EBX for EAX=0x1
  eax = 0x1;
  cpuid(&eax, &ebx, &ecx, &edx);

  if (ecx & cpuid_sse42_bit) {
    host_isa |= CROARING_SSE42;
  }

  if (ecx & cpuid_pclmulqdq_bit) {
    host_isa |= CROARING_PCLMULQDQ;
  }

  return host_isa;
}
#else // fallback


static inline uint32_t dynamic_croaring_detect_supported_architectures() {
  return CROARING_DEFAULT;
}


#endif // end SIMD extension detection code


#if defined(__x86_64__) || defined(_M_AMD64) // x64

#if defined(__cplusplus)
#include <atomic>
static inline uint32_t croaring_detect_supported_architectures() {
    static std::atomic<int> buffer{CROARING_UNINITIALIZED};
    if(buffer == CROARING_UNINITIALIZED) {
      buffer = dynamic_croaring_detect_supported_architectures();
    }
    return buffer;
}
#elif defined(_MSC_VER) && !defined(__clang__)
// Visual Studio does not support C11 atomics.
static inline uint32_t croaring_detect_supported_architectures() {
    static int buffer = CROARING_UNINITIALIZED;
    if(buffer == CROARING_UNINITIALIZED) {
      buffer = dynamic_croaring_detect_supported_architectures();
    }
    return buffer;
}
#else // defined(__cplusplus) and defined(_MSC_VER) && !defined(__clang__)
#if (defined(__GNUC_RH_RELEASE__) && (__GNUC_RH_RELEASE__ != 5)) || (__GNUC__ < 5)
#define ROARING_DISABLE_AVX
#undef __AVX2__
/* CentOS 7 */
static inline uint32_t croaring_detect_supported_architectures() {
  return(dynamic_croaring_detect_supported_architectures());
}
#else
#include <stdatomic.h>
static inline uint32_t croaring_detect_supported_architectures() {
    static _Atomic int buffer = CROARING_UNINITIALIZED;
    if(buffer == CROARING_UNINITIALIZED) {
      buffer = dynamic_croaring_detect_supported_architectures();
    }
    return buffer;
}
#endif // (defined(__GNUC_RH_RELEASE__) && (__GNUC_RH_RELEASE__ != 5)) || (__GNUC__ < 5)
#endif // defined(_MSC_VER) && !defined(__clang__)

#ifdef ROARING_DISABLE_AVX
static inline bool croaring_avx2() {
  return false;
}
#elif defined(__AVX2__)
static inline bool croaring_avx2() {
  return true;
}
#else
static inline bool croaring_avx2() {
  return  (croaring_detect_supported_architectures() & CROARING_AVX2) == CROARING_AVX2;
}
#endif


#else // defined(__x86_64__) || defined(_M_AMD64) // x64

static inline bool croaring_avx2() {
  return false;
}

static inline uint32_t croaring_detect_supported_architectures() {
    // no runtime dispatch
    return dynamic_croaring_detect_supported_architectures();
}
#endif // defined(__x86_64__) || defined(_M_AMD64) // x64

#endif // ROARING_ISADETECTION_H
/* end file include/roaring/isadetection.h */
/* begin file include/roaring/portability.h */
/*
 * portability.h
 *
 */

#ifndef INCLUDE_PORTABILITY_H_
#define INCLUDE_PORTABILITY_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _GNU_SOURCE
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS 1
#endif // __STDC_FORMAT_MACROS

#if !(defined(_POSIX_C_SOURCE)) || (_POSIX_C_SOURCE < 200809L)
#define _POSIX_C_SOURCE 200809L
#endif // !(defined(_POSIX_C_SOURCE)) || (_POSIX_C_SOURCE < 200809L)
#if !(defined(_XOPEN_SOURCE)) || (_XOPEN_SOURCE < 700)
#define _XOPEN_SOURCE 700
#endif // !(defined(_XOPEN_SOURCE)) || (_XOPEN_SOURCE < 700)

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>  // will provide posix_memalign with _POSIX_C_SOURCE as defined above
#if !(defined(__APPLE__)) && !(defined(__FreeBSD__))
#include <malloc.h>  // this should never be needed but there are some reports that it is needed.
#endif

#ifdef __cplusplus
extern "C" {  // portability definitions are in global scope, not a namespace
#endif

#if defined(_MSC_VER) && !defined(__clang__) && !defined(WIN64) && !defined(ROARING_ACK_32BIT)
#pragma message( \
    "You appear to be attempting a 32-bit build under Visual Studio. We recommend a 64-bit build instead.")
#endif

#if defined(__SIZEOF_LONG_LONG__) && __SIZEOF_LONG_LONG__ != 8
#error This code assumes  64-bit long longs (by use of the GCC intrinsics). Your system is not currently supported.
#endif

#if defined(_MSC_VER)
#define __restrict__ __restrict
#endif // defined(_MSC_VER



#if defined(__x86_64__) || defined(_M_X64)
// we have an x64 processor
#define CROARING_IS_X64

#if defined(_MSC_VER) && (_MSC_VER < 1910)
// Old visual studio systems won't support AVX2 well.
#undef CROARING_IS_X64
#endif

#if (defined(__GNUC_RH_RELEASE__) && (__GNUC_RH_RELEASE__ != 5)) || (__GNUC__ < 5)
  /* RH 7 don't have atomic includes */
#undef CROARING_IS_X64
#endif


#if defined(__clang_major__) && (__clang_major__<= 8) && !defined(__AVX2__)
// Older versions of clang have a bug affecting us
// https://stackoverflow.com/questions/57228537/how-does-one-use-pragma-clang-attribute-push-with-c-namespaces
#undef CROARING_IS_X64
#endif

#ifdef ROARING_DISABLE_X64
#undef CROARING_IS_X64
#endif
// we include the intrinsic header
#ifndef _MSC_VER
/* Non-Microsoft C/C++-compatible compiler */
#include <x86intrin.h>  // on some recent GCC, this will declare posix_memalign
#endif // _MSC_VER
#endif // defined(__x86_64__) || defined(_M_X64)

#if !defined(USENEON) && !defined(DISABLENEON) && defined(__ARM_NEON)
#  define USENEON
#endif
#if defined(USENEON)
#  include <arm_neon.h>
#endif

#ifndef _MSC_VER
/* Non-Microsoft C/C++-compatible compiler, assumes that it supports inline
 * assembly */
#define ROARING_INLINE_ASM
#endif  // _MSC_VER


#ifdef _MSC_VER
/* Microsoft C/C++-compatible compiler */
#include <intrin.h>

#ifndef __clang__  // if one compiles with MSVC *with* clang, then these
                   // intrinsics are defined!!!
// sadly there is no way to check whether we are missing these intrinsics
// specifically.

/* wrappers for Visual Studio built-ins that look like gcc built-ins */
/* result might be undefined when input_num is zero */
static inline int __builtin_ctzll(unsigned long long input_num) {
    unsigned long index;
#ifdef WIN64  // highly recommended!!!
    _BitScanForward64(&index, input_num);
#else  // if we must support 32-bit Windows
    if ((uint32_t)input_num != 0) {
        _BitScanForward(&index, (uint32_t)input_num);
    } else {
        _BitScanForward(&index, (uint32_t)(input_num >> 32));
        index += 32;
    }
#endif
    return index;
}

/* result might be undefined when input_num is zero */
static inline int __builtin_clzll(unsigned long long input_num) {
    unsigned long index;
#ifdef WIN64  // highly recommended!!!
    _BitScanReverse64(&index, input_num);
#else  // if we must support 32-bit Windows
    if (input_num > 0xFFFFFFFF) {
        _BitScanReverse(&index, (uint32_t)(input_num >> 32));
        index += 32;
    } else {
        _BitScanReverse(&index, (uint32_t)(input_num));
    }
#endif
    return 63 - index;
}


/* software implementation avoids POPCNT */
/*static inline int __builtin_popcountll(unsigned long long input_num) {
  const uint64_t m1 = 0x5555555555555555; //binary: 0101...
  const uint64_t m2 = 0x3333333333333333; //binary: 00110011..
  const uint64_t m4 = 0x0f0f0f0f0f0f0f0f; //binary:  4 zeros,  4 ones ...
  const uint64_t h01 = 0x0101010101010101; //the sum of 256 to the power of 0,1,2,3...

  input_num -= (input_num >> 1) & m1;
  input_num = (input_num & m2) + ((input_num >> 2) & m2);
  input_num = (input_num + (input_num >> 4)) & m4;
  return (input_num * h01) >> 56;
}*/

/* Use #define so this is effective even under /Ob0 (no inline) */
#define __builtin_unreachable() __assume(0)
#endif

#endif

// without the following, we get lots of warnings about posix_memalign
#ifndef __cplusplus
extern int posix_memalign(void **__memptr, size_t __alignment, size_t __size);
#endif  //__cplusplus // C++ does not have a well defined signature

// portable version of  posix_memalign
static inline void *roaring_bitmap_aligned_malloc(size_t alignment, size_t size) {
    void *p;
#ifdef _MSC_VER
    p = _aligned_malloc(size, alignment);
#elif defined(__MINGW32__) || defined(__MINGW64__)
    p = __mingw_aligned_malloc(size, alignment);
#else
    // somehow, if this is used before including "x86intrin.h", it creates an
    // implicit defined warning.
    if (posix_memalign(&p, alignment, size) != 0) return NULL;
#endif
    return p;
}

static inline void roaring_bitmap_aligned_free(void *memblock) {
#ifdef _MSC_VER
    _aligned_free(memblock);
#elif defined(__MINGW32__) || defined(__MINGW64__)
    __mingw_aligned_free(memblock);
#else
    ndpi_free(memblock);
#endif
}

#if defined(_MSC_VER)
#define ALIGNED(x) __declspec(align(x))
#else
#if defined(__GNUC__)
#define ALIGNED(x) __attribute__((aligned(x)))
#endif
#endif

#ifdef __GNUC__
#define WARN_UNUSED __attribute__((warn_unused_result))
#else
#define WARN_UNUSED
#endif

#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100)

static inline int hammingbackup(uint64_t x) {
  uint64_t c1 = UINT64_C(0x5555555555555555);
  uint64_t c2 = UINT64_C(0x3333333333333333);
  uint64_t c4 = UINT64_C(0x0F0F0F0F0F0F0F0F);
  x -= (x >> 1) & c1;
  x = (( x >> 2) & c2) + (x & c2); x=(x +(x>>4))&c4;
  x *= UINT64_C(0x0101010101010101);
  return x >> 56;
}

static inline int hamming(uint64_t x) {
#if defined(WIN64) && defined(_MSC_VER) && !defined(__clang__)
#ifdef _M_ARM64
  return hammingbackup(x);
  // (int) _CountOneBits64(x); is unavailable
#else  // _M_ARM64
  return (int) __popcnt64(x);
#endif // _M_ARM64
#elif defined(WIN32) && defined(_MSC_VER) && !defined(__clang__)
#ifdef _M_ARM
  return hammingbackup(x);
  // _CountOneBits is unavailable
#else // _M_ARM
    return (int) __popcnt(( unsigned int)x) + (int)  __popcnt(( unsigned int)(x>>32));
#endif // _M_ARM
#else
    return __builtin_popcountll(x);
#endif
}

#ifndef UINT64_C
#define UINT64_C(c) (c##ULL)
#endif // UINT64_C

#ifndef UINT32_C
#define UINT32_C(c) (c##UL)
#endif // UINT32_C

#ifdef __cplusplus
}  // extern "C" {
#endif // __cplusplus


// this is almost standard?
#undef STRINGIFY_IMPLEMENTATION_
#undef STRINGIFY
#define STRINGIFY_IMPLEMENTATION_(a) #a
#define STRINGIFY(a) STRINGIFY_IMPLEMENTATION_(a)

// Our fast kernels require 64-bit systems.
//
// On 32-bit x86, we lack 64-bit popcnt, lzcnt, blsr instructions.
// Furthermore, the number of SIMD registers is reduced.
//
// On 32-bit ARM, we would have smaller registers.
//
// The library should still have the fallback kernel. It is
// slower, but it should run everywhere.

//
// Enable valid runtime implementations, and select CROARING_BUILTIN_IMPLEMENTATION
//

// We are going to use runtime dispatch.
#ifdef CROARING_IS_X64
#ifdef __clang__
// clang does not have GCC push pop
// warning: clang attribute push can't be used within a namespace in clang up
// til 8.0 so CROARING_TARGET_REGION and CROARING_UNTARGET_REGION must be *outside* of a
// namespace.
#define CROARING_TARGET_REGION(T)                                                       \
  _Pragma(STRINGIFY(                                                           \
      clang attribute push(__attribute__((target(T))), apply_to = function)))
#define CROARING_UNTARGET_REGION _Pragma("clang attribute pop")
#elif defined(__GNUC__)
// GCC is easier
#define CROARING_TARGET_REGION(T)                                                       \
  _Pragma("GCC push_options") _Pragma(STRINGIFY(GCC target(T)))
#define CROARING_UNTARGET_REGION _Pragma("GCC pop_options")
#endif // clang then gcc

#endif // CROARING_IS_X64

// Default target region macros don't do anything.
#ifndef CROARING_TARGET_REGION
#define CROARING_TARGET_REGION(T)
#define CROARING_UNTARGET_REGION
#endif

#define CROARING_TARGET_AVX2 CROARING_TARGET_REGION("avx2,bmi,pclmul,lzcnt")

#ifdef __AVX2__
// No need for runtime dispatching.
// It is unnecessary and harmful to old clang to tag regions.
#undef CROARING_TARGET_AVX2
#define CROARING_TARGET_AVX2
#undef CROARING_UNTARGET_REGION
#define CROARING_UNTARGET_REGION
#endif

#endif /* INCLUDE_PORTABILITY_H_ */
/* end file include/roaring/portability.h */
/* begin file include/roaring/containers/perfparameters.h */
#ifndef PERFPARAMETERS_H_
#define PERFPARAMETERS_H_

#include <stdbool.h>

#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/**
During lazy computations, we can transform array containers into bitset
containers as
long as we can expect them to have  ARRAY_LAZY_LOWERBOUND values.
*/
enum { ARRAY_LAZY_LOWERBOUND = 1024 };

/* default initial size of a run container
   setting it to zero delays the malloc.*/
enum { RUN_DEFAULT_INIT_SIZE = 0 };

/* default initial size of an array container
   setting it to zero delays the malloc */
enum { ARRAY_DEFAULT_INIT_SIZE = 0 };

/* automatic bitset conversion during lazy or */
#ifndef LAZY_OR_BITSET_CONVERSION
#define LAZY_OR_BITSET_CONVERSION true
#endif

/* automatically attempt to convert a bitset to a full run during lazy
 * evaluation */
#ifndef LAZY_OR_BITSET_CONVERSION_TO_FULL
#define LAZY_OR_BITSET_CONVERSION_TO_FULL true
#endif

/* automatically attempt to convert a bitset to a full run */
#ifndef OR_BITSET_CONVERSION_TO_FULL
#define OR_BITSET_CONVERSION_TO_FULL true
#endif

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif
/* end file include/roaring/containers/perfparameters.h */
/* begin file include/roaring/containers/container_defs.h */
/*
 * container_defs.h
 *
 * Unlike containers.h (which is a file aggregating all the container includes,
 * like array.h, bitset.h, and run.h) this is a file included BY those headers
 * to do things like define the container base class `container_t`.
 */

#ifndef INCLUDE_CONTAINERS_CONTAINER_DEFS_H_
#define INCLUDE_CONTAINERS_CONTAINER_DEFS_H_

#ifdef __cplusplus
    #include <type_traits>  // used by casting helper for compile-time check
#endif

// The preferences are a separate file to separate out tweakable parameters

#ifdef __cplusplus
namespace roaring { namespace internal {  // No extern "C" (contains template)
#endif


/*
 * Since roaring_array_t's definition is not opaque, the container type is
 * part of the API.  If it's not going to be `void*` then it needs a name, and
 * expectations are to prefix C library-exported names with `roaring_` etc.
 *
 * Rather than force the whole codebase to use the name `roaring_container_t`,
 * the few API appearances use the macro ROARING_CONTAINER_T.  Those includes
 * are prior to containers.h, so make a short private alias of `container_t`.
 * Then undefine the awkward macro so it's not used any more than it has to be.
 */
typedef ROARING_CONTAINER_T container_t;
#undef ROARING_CONTAINER_T


/*
 * See ROARING_CONTAINER_T for notes on using container_t as a base class.
 * This macro helps make the following pattern look nicer:
 *
 *     #ifdef __cplusplus
 *     struct roaring_array_s : public container_t {
 *     #else
 *     struct roaring_array_s {
 *     #endif
 *         int32_t cardinality;
 *         int32_t capacity;
 *         uint16_t *array;
 *     }
 */
#if defined(__cplusplus)
    #define STRUCT_CONTAINER(name) \
        struct name : public container_t  /* { ... } */
#else
    #define STRUCT_CONTAINER(name) \
        struct name  /* { ... } */
#endif


/**
 * Since container_t* is not void* in C++, "dangerous" casts are not needed to
 * downcast; only a static_cast<> is needed.  Define a macro for static casting
 * which helps make casts more visible, and catches problems at compile-time
 * when building the C sources in C++ mode:
 * 
 *     void some_func(container_t **c, ...) {  // double pointer, not single
 *         array_container_t *ac1 = (array_container_t *)(c);  // uncaught!!
 * 
 *         array_container_t *ac2 = CAST(array_container_t *, c)  // C++ errors
 *         array_container_t *ac3 = CAST_array(c);  // shorthand for #2, errors
 *     }
 *
 * Trickier to do is a cast from `container**` to `array_container_t**`.  This
 * needs a reinterpret_cast<>, which sacrifices safety...so a template is used
 * leveraging <type_traits> to make sure it's legal in the C++ build.
 */
#ifdef __cplusplus    
    #define CAST(type,value)            static_cast<type>(value)
    #define movable_CAST(type,value)    movable_CAST_HELPER<type>(value)

    template<typename PPDerived, typename Base>
    PPDerived movable_CAST_HELPER(Base **ptr_to_ptr) {
        typedef typename std::remove_pointer<PPDerived>::type PDerived;
        typedef typename std::remove_pointer<PDerived>::type Derived;
        static_assert(
            std::is_base_of<Base, Derived>::value,
            "use movable_CAST() for container_t** => xxx_container_t**"
        );
        return reinterpret_cast<Derived**>(ptr_to_ptr);
    }
#else
    #define CAST(type,value)            ((type)value)
    #define movable_CAST(type, value)   ((type)value)
#endif

// Use for converting e.g. an `array_container_t**` to a `container_t**`
//
#define movable_CAST_base(c)   movable_CAST(container_t **, c)


#ifdef __cplusplus
} }  // namespace roaring { namespace internal {
#endif

#endif  /* INCLUDE_CONTAINERS_CONTAINER_DEFS_H_ */
/* end file include/roaring/containers/container_defs.h */
/* begin file include/roaring/array_util.h */
#ifndef ARRAY_UTIL_H
#define ARRAY_UTIL_H

#include <stddef.h>  // for size_t
#include <stdint.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/*
 *  Good old binary search.
 *  Assumes that array is sorted, has logarithmic complexity.
 *  if the result is x, then:
 *     if ( x>0 )  you have array[x] = ikey
 *     if ( x<0 ) then inserting ikey at position -x-1 in array (insuring that array[-x-1]=ikey)
 *                   keys the array sorted.
 */
static inline int32_t binarySearch(const uint16_t *array, int32_t lenarray,
                            uint16_t ikey) {
    int32_t low = 0;
    int32_t high = lenarray - 1;
    while (low <= high) {
        int32_t middleIndex = (low + high) >> 1;
        uint16_t middleValue = array[middleIndex];
        if (middleValue < ikey) {
            low = middleIndex + 1;
        } else if (middleValue > ikey) {
            high = middleIndex - 1;
        } else {
            return middleIndex;
        }
    }
    return -(low + 1);
}

/**
 * Galloping search
 * Assumes that array is sorted, has logarithmic complexity.
 * if the result is x, then if x = length, you have that all values in array between pos and length
 *    are smaller than min.
 * otherwise returns the first index x such that array[x] >= min.
 */
static inline int32_t advanceUntil(const uint16_t *array, int32_t pos,
                                   int32_t length, uint16_t min) {
    int32_t lower = pos + 1;

    if ((lower >= length) || (array[lower] >= min)) {
        return lower;
    }

    int32_t spansize = 1;

    while ((lower + spansize < length) && (array[lower + spansize] < min)) {
        spansize <<= 1;
    }
    int32_t upper = (lower + spansize < length) ? lower + spansize : length - 1;

    if (array[upper] == min) {
        return upper;
    }
    if (array[upper] < min) {
        // means
        // array
        // has no
        // item
        // >= min
        // pos = array.length;
        return length;
    }

    // we know that the next-smallest span was too small
    lower += (spansize >> 1);

    int32_t mid = 0;
    while (lower + 1 != upper) {
        mid = (lower + upper) >> 1;
        if (array[mid] == min) {
            return mid;
        } else if (array[mid] < min) {
            lower = mid;
        } else {
            upper = mid;
        }
    }
    return upper;
}

/**
 * Returns number of elements which are less then $ikey.
 * Array elements must be unique and sorted.
 */
static inline int32_t count_less(const uint16_t *array, int32_t lenarray,
                                 uint16_t ikey) {
    if (lenarray == 0) return 0;
    int32_t pos = binarySearch(array, lenarray, ikey);
    return pos >= 0 ? pos : -(pos+1);
}

/**
 * Returns number of elements which are greater then $ikey.
 * Array elements must be unique and sorted.
 */
static inline int32_t count_greater(const uint16_t *array, int32_t lenarray,
                                    uint16_t ikey) {
    if (lenarray == 0) return 0;
    int32_t pos = binarySearch(array, lenarray, ikey);
    if (pos >= 0) {
        return lenarray - (pos+1);
    } else {
        return lenarray - (-pos-1);
    }
}

/**
 * From Schlegel et al., Fast Sorted-Set Intersection using SIMD Instructions
 * Optimized by D. Lemire on May 3rd 2013
 *
 * C should have capacity greater than the minimum of s_1 and s_b + 8
 * where 8 is sizeof(__m128i)/sizeof(uint16_t).
 */
static int32_t intersect_vector16(const uint16_t *__restrict__ A, size_t s_a,
                           const uint16_t *__restrict__ B, size_t s_b,
                           uint16_t *C);

/**
 * Compute the cardinality of the intersection using SSE4 instructions
 */
static int32_t intersect_vector16_cardinality(const uint16_t *__restrict__ A,
                                       size_t s_a,
                                       const uint16_t *__restrict__ B,
                                       size_t s_b);

/* Computes the intersection between one small and one large set of uint16_t.
 * Stores the result into buffer and return the number of elements. */
static int32_t intersect_skewed_uint16(const uint16_t *smallarray, size_t size_s,
                                const uint16_t *largearray, size_t size_l,
                                uint16_t *buffer);

/* Computes the size of the intersection between one small and one large set of
 * uint16_t. */
static int32_t intersect_skewed_uint16_cardinality(const uint16_t *smallarray,
                                            size_t size_s,
                                            const uint16_t *largearray,
                                            size_t size_l);


/* Check whether the size of the intersection between one small and one large set of uint16_t is non-zero. */
static bool intersect_skewed_uint16_nonempty(const uint16_t *smallarray, size_t size_s,
                                const uint16_t *largearray, size_t size_l);
/**
 * Generic intersection function.
 */
static int32_t intersect_uint16(const uint16_t *A, const size_t lenA,
                         const uint16_t *B, const size_t lenB, uint16_t *out);
/**
 * Compute the size of the intersection (generic).
 */
static int32_t intersect_uint16_cardinality(const uint16_t *A, const size_t lenA,
                                     const uint16_t *B, const size_t lenB);

/**
 * Checking whether the size of the intersection  is non-zero.
 */
static bool intersect_uint16_nonempty(const uint16_t *A, const size_t lenA,
                         const uint16_t *B, const size_t lenB);
/**
 * Generic union function.
 */
static size_t union_uint16(const uint16_t *set_1, size_t size_1, const uint16_t *set_2,
                    size_t size_2, uint16_t *buffer);

/**
 * Generic XOR function.
 */
static int32_t xor_uint16(const uint16_t *array_1, int32_t card_1,
                   const uint16_t *array_2, int32_t card_2, uint16_t *out);

/**
 * Generic difference function (ANDNOT).
 */
static int difference_uint16(const uint16_t *a1, int length1, const uint16_t *a2,
                      int length2, uint16_t *a_out);

/**
 * Generic intersection function.
 */
static size_t intersection_uint32(const uint32_t *A, const size_t lenA,
                           const uint32_t *B, const size_t lenB, uint32_t *out);

/**
 * Generic intersection function, returns just the cardinality.
 */
static size_t intersection_uint32_card(const uint32_t *A, const size_t lenA,
                                const uint32_t *B, const size_t lenB);

/**
 * Generic union function.
 */
static size_t union_uint32(const uint32_t *set_1, size_t size_1, const uint32_t *set_2,
                    size_t size_2, uint32_t *buffer);

/**
 * A fast SSE-based union function.
 */
static uint32_t union_vector16(const uint16_t *__restrict__ set_1, uint32_t size_1,
                        const uint16_t *__restrict__ set_2, uint32_t size_2,
                        uint16_t *__restrict__ buffer);
/**
 * A fast SSE-based XOR function.
 */
static uint32_t xor_vector16(const uint16_t *__restrict__ array1, uint32_t length1,
                      const uint16_t *__restrict__ array2, uint32_t length2,
                      uint16_t *__restrict__ output);

/**
 * A fast SSE-based difference function.
 */
static int32_t difference_vector16(const uint16_t *__restrict__ A, size_t s_a,
                            const uint16_t *__restrict__ B, size_t s_b,
                            uint16_t *C);

/**
 * Generic union function, returns just the cardinality.
 */
static size_t union_uint32_card(const uint32_t *set_1, size_t size_1,
                         const uint32_t *set_2, size_t size_2);

/**
* combines union_uint16 and  union_vector16 optimally
*/
static size_t fast_union_uint16(const uint16_t *set_1, size_t size_1, const uint16_t *set_2,
                    size_t size_2, uint16_t *buffer);


static bool memequals(const void *s1, const void *s2, size_t n);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif
/* end file include/roaring/array_util.h */
/* begin file include/roaring/utilasm.h */
/*
 * utilasm.h
 *
 */

#ifndef INCLUDE_UTILASM_H_
#define INCLUDE_UTILASM_H_


#ifdef __cplusplus
extern "C" { namespace roaring {
#endif

#if defined(ROARING_INLINE_ASM)
#define CROARING_ASMBITMANIPOPTIMIZATION  // optimization flag

#define ASM_SHIFT_RIGHT(srcReg, bitsReg, destReg) \
    __asm volatile("shrx %1, %2, %0"              \
                   : "=r"(destReg)                \
                   :             /* write */      \
                   "r"(bitsReg), /* read only */  \
                   "r"(srcReg)   /* read only */  \
                   )

#define ASM_INPLACESHIFT_RIGHT(srcReg, bitsReg)  \
    __asm volatile("shrx %1, %0, %0"             \
                   : "+r"(srcReg)                \
                   :            /* read/write */ \
                   "r"(bitsReg) /* read only */  \
                   )

#define ASM_SHIFT_LEFT(srcReg, bitsReg, destReg) \
    __asm volatile("shlx %1, %2, %0"             \
                   : "=r"(destReg)               \
                   :             /* write */     \
                   "r"(bitsReg), /* read only */ \
                   "r"(srcReg)   /* read only */ \
                   )
// set bit at position testBit within testByte to 1 and
// copy cmovDst to cmovSrc if that bit was previously clear
#define ASM_SET_BIT_INC_WAS_CLEAR(testByte, testBit, count) \
    __asm volatile(                                         \
        "bts %2, %0\n"                                      \
        "sbb $-1, %1\n"                                     \
        : "+r"(testByte), /* read/write */                  \
          "+r"(count)                                       \
        :            /* read/write */                       \
        "r"(testBit) /* read only */                        \
        )

#define ASM_CLEAR_BIT_DEC_WAS_SET(testByte, testBit, count) \
    __asm volatile(                                         \
        "btr %2, %0\n"                                      \
        "sbb $0, %1\n"                                      \
        : "+r"(testByte), /* read/write */                  \
          "+r"(count)                                       \
        :            /* read/write */                       \
        "r"(testBit) /* read only */                        \
        )

#define ASM_BT64(testByte, testBit, count) \
    __asm volatile(                        \
        "bt %2,%1\n"                       \
        "sbb %0,%0" /*could use setb */    \
        : "=r"(count)                      \
        :              /* write */         \
        "r"(testByte), /* read only */     \
        "r"(testBit)   /* read only */     \
        )

#endif

#ifdef __cplusplus
} }  // extern "C" { namespace roaring {
#endif

#endif  /* INCLUDE_UTILASM_H_ */
/* end file include/roaring/utilasm.h */
/* begin file include/roaring/bitset_util.h */
#ifndef BITSET_UTIL_H
#define BITSET_UTIL_H

#include <stdint.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/*
 * Set all bits in indexes [begin,end) to true.
 */
static inline void bitset_set_range(uint64_t *words, uint32_t start,
                                    uint32_t end) {
    if (start == end) return;
    uint32_t firstword = start / 64;
    uint32_t endword = (end - 1) / 64;
    if (firstword == endword) {
        words[firstword] |= ((~UINT64_C(0)) << (start % 64)) &
                             ((~UINT64_C(0)) >> ((~end + 1) % 64));
        return;
    }
    words[firstword] |= (~UINT64_C(0)) << (start % 64);
    uint32_t i; for (i = firstword + 1; i < endword; i++) {
        words[i] = ~UINT64_C(0);
    }
    words[endword] |= (~UINT64_C(0)) >> ((~end + 1) % 64);
}


/*
 * Find the cardinality of the bitset in [begin,begin+lenminusone]
 */
static inline int bitset_lenrange_cardinality(const uint64_t *words,
                                              uint32_t start,
                                              uint32_t lenminusone) {
    uint32_t firstword = start / 64;
    uint32_t endword = (start + lenminusone) / 64;
    if (firstword == endword) {
        return hamming(words[firstword] &
                       ((~UINT64_C(0)) >> ((63 - lenminusone) % 64))
                           << (start % 64));
    }
    int answer = hamming(words[firstword] & ((~UINT64_C(0)) << (start % 64)));
    uint32_t i; for (i = firstword + 1; i < endword; i++) {
        answer += hamming(words[i]);
    }
    answer +=
        hamming(words[endword] &
                (~UINT64_C(0)) >> (((~start + 1) - lenminusone - 1) % 64));
    return answer;
}

/*
 * Check whether the cardinality of the bitset in [begin,begin+lenminusone] is 0
 */
static inline bool bitset_lenrange_empty(const uint64_t *words, uint32_t start,
                                         uint32_t lenminusone) {
    uint32_t firstword = start / 64;
    uint32_t endword = (start + lenminusone) / 64;
    if (firstword == endword) {
        return (words[firstword] & ((~UINT64_C(0)) >> ((63 - lenminusone) % 64))
              << (start % 64)) == 0;
    }
    if (((words[firstword] & ((~UINT64_C(0)) << (start%64)))) != 0) {
        return false;
    }
    uint32_t i; for (i = firstword + 1; i < endword; i++) {
        if (words[i] != 0) {
            return false;
        }
    }
    if ((words[endword] & (~UINT64_C(0)) >> (((~start + 1) - lenminusone - 1) % 64)) != 0) {
        return false;
    }
    return true;
}


/*
 * Set all bits in indexes [begin,begin+lenminusone] to true.
 */
static inline void bitset_set_lenrange(uint64_t *words, uint32_t start,
                                       uint32_t lenminusone) {
    uint32_t firstword = start / 64;
    uint32_t endword = (start + lenminusone) / 64;
    if (firstword == endword) {
        words[firstword] |= ((~UINT64_C(0)) >> ((63 - lenminusone) % 64))
                             << (start % 64);
        return;
    }
    uint64_t temp = words[endword];
    words[firstword] |= (~UINT64_C(0)) << (start % 64);
    uint32_t i; for (i = firstword + 1; i < endword; i += 2)
        words[i] = words[i + 1] = ~UINT64_C(0);
    words[endword] =
        temp | (~UINT64_C(0)) >> (((~start + 1) - lenminusone - 1) % 64);
}

/*
 * Flip all the bits in indexes [begin,end).
 */
static inline void bitset_flip_range(uint64_t *words, uint32_t start,
                                     uint32_t end) {
    if (start == end) return;
    uint32_t firstword = start / 64;
    uint32_t endword = (end - 1) / 64;
    words[firstword] ^= ~((~UINT64_C(0)) << (start % 64));
    uint32_t i; for (i = firstword; i < endword; i++) {
        words[i] = ~words[i];
    }
    words[endword] ^= ((~UINT64_C(0)) >> ((~end + 1) % 64));
}

/*
 * Set all bits in indexes [begin,end) to false.
 */
static inline void bitset_reset_range(uint64_t *words, uint32_t start,
                                      uint32_t end) {
    if (start == end) return;
    uint32_t firstword = start / 64;
    uint32_t endword = (end - 1) / 64;
    if (firstword == endword) {
        words[firstword] &= ~(((~UINT64_C(0)) << (start % 64)) &
                               ((~UINT64_C(0)) >> ((~end + 1) % 64)));
        return;
    }
    words[firstword] &= ~((~UINT64_C(0)) << (start % 64));
    uint32_t i; for (i = firstword + 1; i < endword; i++) {
        words[i] = UINT64_C(0);
    }
    words[endword] &= ~((~UINT64_C(0)) >> ((~end + 1) % 64));
}

/*
 * Given a bitset containing "length" 64-bit words, write out the position
 * of all the set bits to "out", values start at "base".
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 * set.
 *
 * Returns how many values were actually decoded.
 *
 * This function should only be expected to be faster than
 * bitset_extract_setbits
 * when the density of the bitset is high.
 *
 * This function uses AVX2 decoding.
 */
static size_t bitset_extract_setbits_avx2(const uint64_t *words, size_t length,
                                   uint32_t *out, size_t outcapacity,
                                   uint32_t base);

/*
 * Given a bitset containing "length" 64-bit words, write out the position
 * of all the set bits to "out", values start at "base".
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 *set.
 *
 * Returns how many values were actually decoded.
 */
static size_t bitset_extract_setbits(const uint64_t *words, size_t length,
                              uint32_t *out, uint32_t base);

/*
 * Given a bitset containing "length" 64-bit words, write out the position
 * of all the set bits to "out" as 16-bit integers, values start at "base" (can
 *be set to zero)
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 *set.
 *
 * Returns how many values were actually decoded.
 *
 * This function should only be expected to be faster than
 *bitset_extract_setbits_uint16
 * when the density of the bitset is high.
 *
 * This function uses SSE decoding.
 */
static size_t bitset_extract_setbits_sse_uint16(const uint64_t *words, size_t length,
                                         uint16_t *out, size_t outcapacity,
                                         uint16_t base);

/*
 * Given a bitset containing "length" 64-bit words, write out the position
 * of all the set bits to "out",  values start at "base"
 * (can be set to zero)
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 *set.
 *
 * Returns how many values were actually decoded.
 */
static size_t bitset_extract_setbits_uint16(const uint64_t *words, size_t length,
                                     uint16_t *out, uint16_t base);

/*
 * Given two bitsets containing "length" 64-bit words, write out the position
 * of all the common set bits to "out", values start at "base"
 * (can be set to zero)
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 * set.
 *
 * Returns how many values were actually decoded.
 */
static size_t bitset_extract_intersection_setbits_uint16(const uint64_t * __restrict__ words1,
                                                  const uint64_t * __restrict__ words2,
                                                  size_t length, uint16_t *out,
                                                  uint16_t base);

/*
 * Given a bitset having cardinality card, set all bit values in the list (there
 * are length of them)
 * and return the updated cardinality. This evidently assumes that the bitset
 * already contained data.
 */
static uint64_t bitset_set_list_withcard(uint64_t *words, uint64_t card,
                                  const uint16_t *list, uint64_t length);
/*
 * Given a bitset, set all bit values in the list (there
 * are length of them).
 */
static void bitset_set_list(uint64_t *words, const uint16_t *list, uint64_t length);

/*
 * Given a bitset having cardinality card, unset all bit values in the list
 * (there are length of them)
 * and return the updated cardinality. This evidently assumes that the bitset
 * already contained data.
 */
static uint64_t bitset_clear_list(uint64_t *words, uint64_t card, const uint16_t *list,
                           uint64_t length);

/*
 * Given a bitset having cardinality card, toggle all bit values in the list
 * (there are length of them)
 * and return the updated cardinality. This evidently assumes that the bitset
 * already contained data.
 */

static uint64_t bitset_flip_list_withcard(uint64_t *words, uint64_t card,
                                   const uint16_t *list, uint64_t length);

static void bitset_flip_list(uint64_t *words, const uint16_t *list, uint64_t length);

#ifdef CROARING_IS_X64
/***
 * BEGIN Harley-Seal popcount functions.
 */
CROARING_TARGET_AVX2
/**
 * Compute the population count of a 256-bit word
 * This is not especially fast, but it is convenient as part of other functions.
 */
static inline __m256i popcount256(__m256i v) {
    const __m256i lookuppos = _mm256_setr_epi8(
        /* 0 */ 4 + 0, /* 1 */ 4 + 1, /* 2 */ 4 + 1, /* 3 */ 4 + 2,
        /* 4 */ 4 + 1, /* 5 */ 4 + 2, /* 6 */ 4 + 2, /* 7 */ 4 + 3,
        /* 8 */ 4 + 1, /* 9 */ 4 + 2, /* a */ 4 + 2, /* b */ 4 + 3,
        /* c */ 4 + 2, /* d */ 4 + 3, /* e */ 4 + 3, /* f */ 4 + 4,

        /* 0 */ 4 + 0, /* 1 */ 4 + 1, /* 2 */ 4 + 1, /* 3 */ 4 + 2,
        /* 4 */ 4 + 1, /* 5 */ 4 + 2, /* 6 */ 4 + 2, /* 7 */ 4 + 3,
        /* 8 */ 4 + 1, /* 9 */ 4 + 2, /* a */ 4 + 2, /* b */ 4 + 3,
        /* c */ 4 + 2, /* d */ 4 + 3, /* e */ 4 + 3, /* f */ 4 + 4);
    const __m256i lookupneg = _mm256_setr_epi8(
        /* 0 */ 4 - 0, /* 1 */ 4 - 1, /* 2 */ 4 - 1, /* 3 */ 4 - 2,
        /* 4 */ 4 - 1, /* 5 */ 4 - 2, /* 6 */ 4 - 2, /* 7 */ 4 - 3,
        /* 8 */ 4 - 1, /* 9 */ 4 - 2, /* a */ 4 - 2, /* b */ 4 - 3,
        /* c */ 4 - 2, /* d */ 4 - 3, /* e */ 4 - 3, /* f */ 4 - 4,

        /* 0 */ 4 - 0, /* 1 */ 4 - 1, /* 2 */ 4 - 1, /* 3 */ 4 - 2,
        /* 4 */ 4 - 1, /* 5 */ 4 - 2, /* 6 */ 4 - 2, /* 7 */ 4 - 3,
        /* 8 */ 4 - 1, /* 9 */ 4 - 2, /* a */ 4 - 2, /* b */ 4 - 3,
        /* c */ 4 - 2, /* d */ 4 - 3, /* e */ 4 - 3, /* f */ 4 - 4);
    const __m256i low_mask = _mm256_set1_epi8(0x0f);

    const __m256i lo = _mm256_and_si256(v, low_mask);
    const __m256i hi = _mm256_and_si256(_mm256_srli_epi16(v, 4), low_mask);
    const __m256i popcnt1 = _mm256_shuffle_epi8(lookuppos, lo);
    const __m256i popcnt2 = _mm256_shuffle_epi8(lookupneg, hi);
    return _mm256_sad_epu8(popcnt1, popcnt2);
}
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
/**
 * Simple CSA over 256 bits
 */
static inline void CSA(__m256i *h, __m256i *l, __m256i a, __m256i b,
                       __m256i c) {
    const __m256i u = _mm256_xor_si256(a, b);
    *h = _mm256_or_si256(_mm256_and_si256(a, b), _mm256_and_si256(u, c));
    *l = _mm256_xor_si256(u, c);
}
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
/**
 * Fast Harley-Seal AVX population count function
 */
static inline  uint64_t avx2_harley_seal_popcount256(const __m256i *data,
                                                    const uint64_t size) {
    __m256i total = _mm256_setzero_si256();
    __m256i ones = _mm256_setzero_si256();
    __m256i twos = _mm256_setzero_si256();
    __m256i fours = _mm256_setzero_si256();
    __m256i eights = _mm256_setzero_si256();
    __m256i sixteens = _mm256_setzero_si256();
    __m256i twosA, twosB, foursA, foursB, eightsA, eightsB;

    const uint64_t limit = size - size % 16;
    uint64_t i = 0;

    for (; i < limit; i += 16) {
        CSA(&twosA, &ones, ones, _mm256_lddqu_si256(data + i),
            _mm256_lddqu_si256(data + i + 1));
        CSA(&twosB, &ones, ones, _mm256_lddqu_si256(data + i + 2),
            _mm256_lddqu_si256(data + i + 3));
        CSA(&foursA, &twos, twos, twosA, twosB);
        CSA(&twosA, &ones, ones, _mm256_lddqu_si256(data + i + 4),
            _mm256_lddqu_si256(data + i + 5));
        CSA(&twosB, &ones, ones, _mm256_lddqu_si256(data + i + 6),
            _mm256_lddqu_si256(data + i + 7));
        CSA(&foursB, &twos, twos, twosA, twosB);
        CSA(&eightsA, &fours, fours, foursA, foursB);
        CSA(&twosA, &ones, ones, _mm256_lddqu_si256(data + i + 8),
            _mm256_lddqu_si256(data + i + 9));
        CSA(&twosB, &ones, ones, _mm256_lddqu_si256(data + i + 10),
            _mm256_lddqu_si256(data + i + 11));
        CSA(&foursA, &twos, twos, twosA, twosB);
        CSA(&twosA, &ones, ones, _mm256_lddqu_si256(data + i + 12),
            _mm256_lddqu_si256(data + i + 13));
        CSA(&twosB, &ones, ones, _mm256_lddqu_si256(data + i + 14),
            _mm256_lddqu_si256(data + i + 15));
        CSA(&foursB, &twos, twos, twosA, twosB);
        CSA(&eightsB, &fours, fours, foursA, foursB);
        CSA(&sixteens, &eights, eights, eightsA, eightsB);

        total = _mm256_add_epi64(total, popcount256(sixteens));
    }

    total = _mm256_slli_epi64(total, 4);  // * 16
    total = _mm256_add_epi64(
        total, _mm256_slli_epi64(popcount256(eights), 3));  // += 8 * ...
    total = _mm256_add_epi64(
        total, _mm256_slli_epi64(popcount256(fours), 2));  // += 4 * ...
    total = _mm256_add_epi64(
        total, _mm256_slli_epi64(popcount256(twos), 1));  // += 2 * ...
    total = _mm256_add_epi64(total, popcount256(ones));
    for (; i < size; i++)
        total =
            _mm256_add_epi64(total, popcount256(_mm256_lddqu_si256(data + i)));

    return (uint64_t)(_mm256_extract_epi64(total, 0)) +
           (uint64_t)(_mm256_extract_epi64(total, 1)) +
           (uint64_t)(_mm256_extract_epi64(total, 2)) +
           (uint64_t)(_mm256_extract_epi64(total, 3));
}
CROARING_UNTARGET_REGION

#define AVXPOPCNTFNC(opname, avx_intrinsic)                                    \
    static inline uint64_t avx2_harley_seal_popcount256_##opname(              \
        const __m256i *data1, const __m256i *data2, const uint64_t size) {     \
        __m256i total = _mm256_setzero_si256();                                \
        __m256i ones = _mm256_setzero_si256();                                 \
        __m256i twos = _mm256_setzero_si256();                                 \
        __m256i fours = _mm256_setzero_si256();                                \
        __m256i eights = _mm256_setzero_si256();                               \
        __m256i sixteens = _mm256_setzero_si256();                             \
        __m256i twosA, twosB, foursA, foursB, eightsA, eightsB;                \
        __m256i A1, A2;                                                        \
        const uint64_t limit = size - size % 16;                               \
        uint64_t i = 0;                                                        \
        for (; i < limit; i += 16) {                                           \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i),                  \
                               _mm256_lddqu_si256(data2 + i));                 \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 1),              \
                               _mm256_lddqu_si256(data2 + i + 1));             \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 2),              \
                               _mm256_lddqu_si256(data2 + i + 2));             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 3),              \
                               _mm256_lddqu_si256(data2 + i + 3));             \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursA, &twos, twos, twosA, twosB);                           \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 4),              \
                               _mm256_lddqu_si256(data2 + i + 4));             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 5),              \
                               _mm256_lddqu_si256(data2 + i + 5));             \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 6),              \
                               _mm256_lddqu_si256(data2 + i + 6));             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 7),              \
                               _mm256_lddqu_si256(data2 + i + 7));             \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursB, &twos, twos, twosA, twosB);                           \
            CSA(&eightsA, &fours, fours, foursA, foursB);                      \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 8),              \
                               _mm256_lddqu_si256(data2 + i + 8));             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 9),              \
                               _mm256_lddqu_si256(data2 + i + 9));             \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 10),             \
                               _mm256_lddqu_si256(data2 + i + 10));            \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 11),             \
                               _mm256_lddqu_si256(data2 + i + 11));            \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursA, &twos, twos, twosA, twosB);                           \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 12),             \
                               _mm256_lddqu_si256(data2 + i + 12));            \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 13),             \
                               _mm256_lddqu_si256(data2 + i + 13));            \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 14),             \
                               _mm256_lddqu_si256(data2 + i + 14));            \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 15),             \
                               _mm256_lddqu_si256(data2 + i + 15));            \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursB, &twos, twos, twosA, twosB);                           \
            CSA(&eightsB, &fours, fours, foursA, foursB);                      \
            CSA(&sixteens, &eights, eights, eightsA, eightsB);                 \
            total = _mm256_add_epi64(total, popcount256(sixteens));            \
        }                                                                      \
        total = _mm256_slli_epi64(total, 4);                                   \
        total = _mm256_add_epi64(total,                                        \
                                 _mm256_slli_epi64(popcount256(eights), 3));   \
        total =                                                                \
            _mm256_add_epi64(total, _mm256_slli_epi64(popcount256(fours), 2)); \
        total =                                                                \
            _mm256_add_epi64(total, _mm256_slli_epi64(popcount256(twos), 1));  \
        total = _mm256_add_epi64(total, popcount256(ones));                    \
        for (; i < size; i++) {                                                \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i),                  \
                               _mm256_lddqu_si256(data2 + i));                 \
            total = _mm256_add_epi64(total, popcount256(A1));                  \
        }                                                                      \
        return (uint64_t)(_mm256_extract_epi64(total, 0)) +                    \
               (uint64_t)(_mm256_extract_epi64(total, 1)) +                    \
               (uint64_t)(_mm256_extract_epi64(total, 2)) +                    \
               (uint64_t)(_mm256_extract_epi64(total, 3));                     \
    }                                                                          \
    static inline uint64_t avx2_harley_seal_popcount256andstore_##opname(      \
        const __m256i *__restrict__ data1, const __m256i *__restrict__ data2,  \
        __m256i *__restrict__ out, const uint64_t size) {                      \
        __m256i total = _mm256_setzero_si256();                                \
        __m256i ones = _mm256_setzero_si256();                                 \
        __m256i twos = _mm256_setzero_si256();                                 \
        __m256i fours = _mm256_setzero_si256();                                \
        __m256i eights = _mm256_setzero_si256();                               \
        __m256i sixteens = _mm256_setzero_si256();                             \
        __m256i twosA, twosB, foursA, foursB, eightsA, eightsB;                \
        __m256i A1, A2;                                                        \
        const uint64_t limit = size - size % 16;                               \
        uint64_t i = 0;                                                        \
        for (; i < limit; i += 16) {                                           \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i),                  \
                               _mm256_lddqu_si256(data2 + i));                 \
            _mm256_storeu_si256(out + i, A1);                                  \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 1),              \
                               _mm256_lddqu_si256(data2 + i + 1));             \
            _mm256_storeu_si256(out + i + 1, A2);                              \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 2),              \
                               _mm256_lddqu_si256(data2 + i + 2));             \
            _mm256_storeu_si256(out + i + 2, A1);                              \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 3),              \
                               _mm256_lddqu_si256(data2 + i + 3));             \
            _mm256_storeu_si256(out + i + 3, A2);                              \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursA, &twos, twos, twosA, twosB);                           \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 4),              \
                               _mm256_lddqu_si256(data2 + i + 4));             \
            _mm256_storeu_si256(out + i + 4, A1);                              \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 5),              \
                               _mm256_lddqu_si256(data2 + i + 5));             \
            _mm256_storeu_si256(out + i + 5, A2);                              \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 6),              \
                               _mm256_lddqu_si256(data2 + i + 6));             \
            _mm256_storeu_si256(out + i + 6, A1);                              \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 7),              \
                               _mm256_lddqu_si256(data2 + i + 7));             \
            _mm256_storeu_si256(out + i + 7, A2);                              \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursB, &twos, twos, twosA, twosB);                           \
            CSA(&eightsA, &fours, fours, foursA, foursB);                      \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 8),              \
                               _mm256_lddqu_si256(data2 + i + 8));             \
            _mm256_storeu_si256(out + i + 8, A1);                              \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 9),              \
                               _mm256_lddqu_si256(data2 + i + 9));             \
            _mm256_storeu_si256(out + i + 9, A2);                              \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 10),             \
                               _mm256_lddqu_si256(data2 + i + 10));            \
            _mm256_storeu_si256(out + i + 10, A1);                             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 11),             \
                               _mm256_lddqu_si256(data2 + i + 11));            \
            _mm256_storeu_si256(out + i + 11, A2);                             \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursA, &twos, twos, twosA, twosB);                           \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 12),             \
                               _mm256_lddqu_si256(data2 + i + 12));            \
            _mm256_storeu_si256(out + i + 12, A1);                             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 13),             \
                               _mm256_lddqu_si256(data2 + i + 13));            \
            _mm256_storeu_si256(out + i + 13, A2);                             \
            CSA(&twosA, &ones, ones, A1, A2);                                  \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 14),             \
                               _mm256_lddqu_si256(data2 + i + 14));            \
            _mm256_storeu_si256(out + i + 14, A1);                             \
            A2 = avx_intrinsic(_mm256_lddqu_si256(data1 + i + 15),             \
                               _mm256_lddqu_si256(data2 + i + 15));            \
            _mm256_storeu_si256(out + i + 15, A2);                             \
            CSA(&twosB, &ones, ones, A1, A2);                                  \
            CSA(&foursB, &twos, twos, twosA, twosB);                           \
            CSA(&eightsB, &fours, fours, foursA, foursB);                      \
            CSA(&sixteens, &eights, eights, eightsA, eightsB);                 \
            total = _mm256_add_epi64(total, popcount256(sixteens));            \
        }                                                                      \
        total = _mm256_slli_epi64(total, 4);                                   \
        total = _mm256_add_epi64(total,                                        \
                                 _mm256_slli_epi64(popcount256(eights), 3));   \
        total =                                                                \
            _mm256_add_epi64(total, _mm256_slli_epi64(popcount256(fours), 2)); \
        total =                                                                \
            _mm256_add_epi64(total, _mm256_slli_epi64(popcount256(twos), 1));  \
        total = _mm256_add_epi64(total, popcount256(ones));                    \
        for (; i < size; i++) {                                                \
            A1 = avx_intrinsic(_mm256_lddqu_si256(data1 + i),                  \
                               _mm256_lddqu_si256(data2 + i));                 \
            _mm256_storeu_si256(out + i, A1);                                  \
            total = _mm256_add_epi64(total, popcount256(A1));                  \
        }                                                                      \
        return (uint64_t)(_mm256_extract_epi64(total, 0)) +                    \
               (uint64_t)(_mm256_extract_epi64(total, 1)) +                    \
               (uint64_t)(_mm256_extract_epi64(total, 2)) +                    \
               (uint64_t)(_mm256_extract_epi64(total, 3));                     \
    }

CROARING_TARGET_AVX2
AVXPOPCNTFNC(or, _mm256_or_si256)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVXPOPCNTFNC(union, _mm256_or_si256)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVXPOPCNTFNC(and, _mm256_and_si256)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVXPOPCNTFNC(intersection, _mm256_and_si256)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVXPOPCNTFNC (xor, _mm256_xor_si256)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVXPOPCNTFNC(andnot, _mm256_andnot_si256)
CROARING_UNTARGET_REGION

/***
 * END Harley-Seal popcount functions.
 */

#endif  // CROARING_IS_X64

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal
#endif

#endif
/* end file include/roaring/bitset_util.h */
/* begin file include/roaring/containers/array.h */
/*
 * array.h
 *
 */

#ifndef INCLUDE_CONTAINERS_ARRAY_H_
#define INCLUDE_CONTAINERS_ARRAY_H_

#include <string.h>



#ifdef __cplusplus
extern "C" { namespace roaring {

// Note: in pure C++ code, you should avoid putting `using` in header files
using api::roaring_iterator;
using api::roaring_iterator64;

namespace internal {
#endif

/* Containers with DEFAULT_MAX_SIZE or less integers should be arrays */
enum { DEFAULT_MAX_SIZE = 4096 };

/* struct array_container - sparse representation of a bitmap
 *
 * @cardinality: number of indices in `array` (and the bitmap)
 * @capacity:    allocated size of `array`
 * @array:       sorted list of integers
 */
STRUCT_CONTAINER(array_container_s) {
    int32_t cardinality;
    int32_t capacity;
    uint16_t *array;
};

typedef struct array_container_s array_container_t;

#define CAST_array(c)         CAST(array_container_t *, c)  // safer downcast
#define const_CAST_array(c)   CAST(const array_container_t *, c)
#define movable_CAST_array(c) movable_CAST(array_container_t **, c)

/* Create a new array with default. Return NULL in case of failure. See also
 * array_container_create_given_capacity. */
static array_container_t *array_container_create(void);

/* Create a new array with a specified capacity size. Return NULL in case of
 * failure. */
static array_container_t *array_container_create_given_capacity(int32_t size);

/* Create a new array containing all values in [min,max). */
static array_container_t * array_container_create_range(uint32_t min, uint32_t max);

/*
 * Shrink the capacity to the actual size, return the number of bytes saved.
 */
static int array_container_shrink_to_fit(array_container_t *src);

/* Free memory owned by `array'. */
static void array_container_free(array_container_t *array);

/* Duplicate container */
static array_container_t *array_container_clone(const array_container_t *src);

/* Get the cardinality of `array'. */
static inline int array_container_cardinality(const array_container_t *array) {
    return array->cardinality;
}

static inline bool array_container_nonzero_cardinality(
    const array_container_t *array) {
    return array->cardinality > 0;
}

/* Copy one container into another. We assume that they are distinct. */
static void array_container_copy(const array_container_t *src, array_container_t *dst);

/*  Add all the values in [min,max) (included) at a distance k*step from min.
    The container must have a size less or equal to DEFAULT_MAX_SIZE after this
   addition. */
static void array_container_add_from_range(array_container_t *arr, uint32_t min,
                                    uint32_t max, uint16_t step);

/* Set the cardinality to zero (does not release memory). */
static inline void array_container_clear(array_container_t *array) {
    array->cardinality = 0;
}

static inline bool array_container_empty(const array_container_t *array) {
    return array->cardinality == 0;
}

/* check whether the cardinality is equal to the capacity (this does not mean
* that it contains 1<<16 elements) */
static inline bool array_container_full(const array_container_t *array) {
    return array->cardinality == array->capacity;
}


/* Compute the union of `src_1' and `src_2' and write the result to `dst'
 * It is assumed that `dst' is distinct from both `src_1' and `src_2'. */
static void array_container_union(const array_container_t *src_1,
                           const array_container_t *src_2,
                           array_container_t *dst);

/* symmetric difference, see array_container_union */
static void array_container_xor(const array_container_t *array_1,
                         const array_container_t *array_2,
                         array_container_t *out);

/* Computes the intersection of src_1 and src_2 and write the result to
 * dst. It is assumed that dst is distinct from both src_1 and src_2. */
static void array_container_intersection(const array_container_t *src_1,
                                  const array_container_t *src_2,
                                  array_container_t *dst);

/* Check whether src_1 and src_2 intersect. */
static bool array_container_intersect(const array_container_t *src_1,
                                  const array_container_t *src_2);


/* computers the size of the intersection between two arrays.
 */
static int array_container_intersection_cardinality(const array_container_t *src_1,
                                             const array_container_t *src_2);

/* computes the intersection of array1 and array2 and write the result to
 * array1.
 * */
static void array_container_intersection_inplace(array_container_t *src_1,
                                          const array_container_t *src_2);

/*
 * Write out the 16-bit integers contained in this container as a list of 32-bit
 * integers using base
 * as the starting value (it might be expected that base has zeros in its 16
 * least significant bits).
 * The function returns the number of values written.
 * The caller is responsible for allocating enough memory in out.
 */
static int array_container_to_uint32_array(void *vout, const array_container_t *cont,
                                    uint32_t base);

/* Compute the number of runs */
static int32_t array_container_number_of_runs(const array_container_t *ac);

/*
 * Print this container using printf (useful for debugging).
 */
static void array_container_printf(const array_container_t *v);

/*
 * Print this container using printf as a comma-separated list of 32-bit
 * integers starting at base.
 */
static void array_container_printf_as_uint32_array(const array_container_t *v,
                                            uint32_t base);

/**
 * Return the serialized size in bytes of a container having cardinality "card".
 */
static inline int32_t array_container_serialized_size_in_bytes(int32_t card) {
    return card * 2 + 2;
}

/**
 * Increase capacity to at least min.
 * Whether the existing data needs to be copied over depends on the "preserve"
 * parameter. If preserve is false, then the new content will be uninitialized,
 * otherwise the old content is copied.
 */
static void array_container_grow(array_container_t *container, int32_t min,
                          bool preserve);

static bool array_container_iterate(const array_container_t *cont, uint32_t base,
                             roaring_iterator iterator, void *ptr);
static bool array_container_iterate64(const array_container_t *cont, uint32_t base,
                               roaring_iterator64 iterator, uint64_t high_bits,
                               void *ptr);

/**
 * Writes the underlying array to buf, outputs how many bytes were written.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes written should be
 * array_container_size_in_bytes(container).
 *
 */
static int32_t array_container_write(const array_container_t *container, char *buf);
/**
 * Reads the instance from buf, outputs how many bytes were read.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes read should be array_container_size_in_bytes(container).
 * You need to provide the (known) cardinality.
 */
static int32_t array_container_read(int32_t cardinality, array_container_t *container,
                             const char *buf);

/**
 * Return the serialized size in bytes of a container (see
 * bitset_container_write)
 * This is meant to be compatible with the Java and Go versions of Roaring and
 * assumes
 * that the cardinality of the container is already known.
 *
 */
static inline int32_t array_container_size_in_bytes(
    const array_container_t *container) {
    return container->cardinality * sizeof(uint16_t);
}

/**
 * Return true if the two arrays have the same content.
 */
static inline bool array_container_equals(
    const array_container_t *container1,
    const array_container_t *container2) {

    if (container1->cardinality != container2->cardinality) {
        return false;
    }
    return memequals(container1->array, container2->array, container1->cardinality*2);
}

/**
 * Return true if container1 is a subset of container2.
 */
static bool array_container_is_subset(const array_container_t *container1,
                               const array_container_t *container2);

/**
 * If the element of given rank is in this container, supposing that the first
 * element has rank start_rank, then the function returns true and sets element
 * accordingly.
 * Otherwise, it returns false and update start_rank.
 */
static inline bool array_container_select(const array_container_t *container,
                                          uint32_t *start_rank, uint32_t rank,
                                          uint32_t *element) {
    int card = array_container_cardinality(container);
    if (*start_rank + card <= rank) {
        *start_rank += card;
        return false;
    } else {
        *element = container->array[rank - *start_rank];
        return true;
    }
}

/* Computes the  difference of array1 and array2 and write the result
 * to array out.
 * Array out does not need to be distinct from array_1
 */
static void array_container_andnot(const array_container_t *array_1,
                            const array_container_t *array_2,
                            array_container_t *out);

/* Append x to the set. Assumes that the value is larger than any preceding
 * values.  */
static inline void array_container_append(array_container_t *arr,
                                          uint16_t pos) {
    const int32_t capacity = arr->capacity;

    if (array_container_full(arr)) {
        array_container_grow(arr, capacity + 1, true);
    }

    arr->array[arr->cardinality++] = pos;
}

/**
 * Add value to the set if final cardinality doesn't exceed max_cardinality.
 * Return code:
 * 1  -- value was added
 * 0  -- value was already present
 * -1 -- value was not added because cardinality would exceed max_cardinality
 */
static inline int array_container_try_add(array_container_t *arr, uint16_t value,
                                          int32_t max_cardinality) {
    const int32_t cardinality = arr->cardinality;

    // best case, we can append.
    if ((array_container_empty(arr) || arr->array[cardinality - 1] < value) &&
        cardinality < max_cardinality) {
        array_container_append(arr, value);
        return 1;
    }

    const int32_t loc = binarySearch(arr->array, cardinality, value);

    if (loc >= 0) {
        return 0;
    } else if (cardinality < max_cardinality) {
        if (array_container_full(arr)) {
            array_container_grow(arr, arr->capacity + 1, true);
        }
        const int32_t insert_idx = -loc - 1;
        memmove(arr->array + insert_idx + 1, arr->array + insert_idx,
                (cardinality - insert_idx) * sizeof(uint16_t));
        arr->array[insert_idx] = value;
        arr->cardinality++;
        return 1;
    } else {
        return -1;
    }
}

/* Add value to the set. Returns true if x was not already present.  */
static inline bool array_container_add(array_container_t *arr, uint16_t value) {
    return array_container_try_add(arr, value, INT32_MAX) == 1;
}

/* Remove x from the set. Returns true if x was present.  */
static inline bool array_container_remove(array_container_t *arr,
                                          uint16_t pos) {
    const int32_t idx = binarySearch(arr->array, arr->cardinality, pos);
    const bool is_present = idx >= 0;
    if (is_present) {
        memmove(arr->array + idx, arr->array + idx + 1,
                (arr->cardinality - idx - 1) * sizeof(uint16_t));
        arr->cardinality--;
    }

    return is_present;
}

/* Check whether x is present.  */
static inline bool array_container_contains(const array_container_t *arr,
                                     uint16_t pos) {
    //    return binarySearch(arr->array, arr->cardinality, pos) >= 0;
    // binary search with fallback to linear search for short ranges
    int32_t low = 0;
    const uint16_t * carr = (const uint16_t *) arr->array;
    int32_t high = arr->cardinality - 1;
    //    while (high - low >= 0) {
    while(high >= low + 16) {
        int32_t middleIndex = (low + high)>>1;
        uint16_t middleValue = carr[middleIndex];
        if (middleValue < pos) {
            low = middleIndex + 1;
        } else if (middleValue > pos) {
            high = middleIndex - 1;
        } else {
            return true;
        }
    }

    int i;
    for (i=low; i <= high; i++) {
        uint16_t v = carr[i];
        if (v == pos) {
            return true;
        }
        if ( v > pos ) return false;
    }
    return false;

}

//* Check whether a range of values from range_start (included) to range_end (excluded) is present. */
static inline bool array_container_contains_range(const array_container_t *arr,
                                                    uint32_t range_start, uint32_t range_end) {

    const uint16_t rs_included = range_start;
    const uint16_t re_included = range_end - 1;

    const uint16_t *carr = (const uint16_t *) arr->array;

    const int32_t start = advanceUntil(carr, -1, arr->cardinality, rs_included);
    const int32_t end = advanceUntil(carr, start - 1, arr->cardinality, re_included);

    return (start < arr->cardinality) && (end < arr->cardinality)
            && (((uint16_t)(end - start)) == re_included - rs_included)
            && (carr[start] == rs_included) && (carr[end] == re_included);
}

/* Returns the smallest value (assumes not empty) */
static inline uint16_t array_container_minimum(const array_container_t *arr) {
    if (arr->cardinality == 0) return 0;
    return arr->array[0];
}

/* Returns the largest value (assumes not empty) */
static inline uint16_t array_container_maximum(const array_container_t *arr) {
    if (arr->cardinality == 0) return 0;
    return arr->array[arr->cardinality - 1];
}

/* Returns the number of values equal or smaller than x */
static inline int array_container_rank(const array_container_t *arr, uint16_t x) {
    const int32_t idx = binarySearch(arr->array, arr->cardinality, x);
    const bool is_present = idx >= 0;
    if (is_present) {
        return idx + 1;
    } else {
        return -idx - 1;
    }
}

/* Returns the index of the first value equal or smaller than x, or -1 */
static inline int array_container_index_equalorlarger(const array_container_t *arr, uint16_t x) {
    const int32_t idx = binarySearch(arr->array, arr->cardinality, x);
    const bool is_present = idx >= 0;
    if (is_present) {
        return idx;
    } else {
        int32_t candidate = - idx - 1;
        if(candidate < arr->cardinality) return candidate;
        return -1;
    }
}

/*
 * Adds all values in range [min,max] using hint:
 *   nvals_less is the number of array values less than $min
 *   nvals_greater is the number of array values greater than $max
 */
static inline void array_container_add_range_nvals(array_container_t *array,
                                                   uint32_t min, uint32_t max,
                                                   int32_t nvals_less,
                                                   int32_t nvals_greater) {
    int32_t union_cardinality = nvals_less + (max - min + 1) + nvals_greater;
    if (union_cardinality > array->capacity) {
        array_container_grow(array, union_cardinality, true);
    }
    memmove(&(array->array[union_cardinality - nvals_greater]),
            &(array->array[array->cardinality - nvals_greater]),
            nvals_greater * sizeof(uint16_t));
    uint32_t i; for (i = 0; i <= max - min; i++) {
        array->array[nvals_less + i] = min + i;
    }
    array->cardinality = union_cardinality;
}

/**
 * Adds all values in range [min,max].
 */
static inline void array_container_add_range(array_container_t *array,
                                             uint32_t min, uint32_t max) {
    int32_t nvals_greater = count_greater(array->array, array->cardinality, max);
    int32_t nvals_less = count_less(array->array, array->cardinality - nvals_greater, min);
    array_container_add_range_nvals(array, min, max, nvals_less, nvals_greater);
}

/*
 * Removes all elements array[pos] .. array[pos+count-1]
 */
static inline void array_container_remove_range(array_container_t *array,
                                                uint32_t pos, uint32_t count) {
  if (count != 0) {
      memmove(&(array->array[pos]), &(array->array[pos+count]),
              (array->cardinality - pos - count) * sizeof(uint16_t));
      array->cardinality -= count;
  }
}

#ifdef __cplusplus
} } } // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_ARRAY_H_ */
/* end file include/roaring/containers/array.h */
/* begin file include/roaring/containers/bitset.h */
/*
 * bitset.h
 *
 */

#ifndef INCLUDE_CONTAINERS_BITSET_H_
#define INCLUDE_CONTAINERS_BITSET_H_

#include <stdbool.h>
#include <stdint.h>



#ifdef __cplusplus
extern "C" { namespace roaring {

// Note: in pure C++ code, you should avoid putting `using` in header files
using api::roaring_iterator;
using api::roaring_iterator64;

namespace internal {
#endif



enum {
    BITSET_CONTAINER_SIZE_IN_WORDS = (1 << 16) / 64,
    BITSET_UNKNOWN_CARDINALITY = -1
};

STRUCT_CONTAINER(bitset_container_s) {
    int32_t cardinality;
    uint64_t *words;
};

typedef struct bitset_container_s bitset_container_t;

#define CAST_bitset(c)         CAST(bitset_container_t *, c)  // safer downcast
#define const_CAST_bitset(c)   CAST(const bitset_container_t *, c)
#define movable_CAST_bitset(c) movable_CAST(bitset_container_t **, c)

/* Create a new bitset. Return NULL in case of failure. */
static bitset_container_t *bitset_container_create(void);

/* Free memory. */
static void bitset_container_free(bitset_container_t *bitset);

/* Clear bitset (sets bits to 0). */
static void bitset_container_clear(bitset_container_t *bitset);

/* Set all bits to 1. */
static void bitset_container_set_all(bitset_container_t *bitset);

/* Duplicate bitset */
static bitset_container_t *bitset_container_clone(const bitset_container_t *src);

/* Set the bit in [begin,end). WARNING: as of April 2016, this method is slow
 * and
 * should not be used in performance-sensitive code. Ever.  */
static void bitset_container_set_range(bitset_container_t *bitset, uint32_t begin,
                                uint32_t end);

#if defined(CROARING_ASMBITMANIPOPTIMIZATION) && defined(__AVX2__)
/* Set the ith bit.  */
static inline void bitset_container_set(bitset_container_t *bitset,
                                        uint16_t pos) {
    uint64_t shift = 6;
    uint64_t offset;
    uint64_t p = pos;
    ASM_SHIFT_RIGHT(p, shift, offset);
    uint64_t load = bitset->words[offset];
    ASM_SET_BIT_INC_WAS_CLEAR(load, p, bitset->cardinality);
    bitset->words[offset] = load;
}

/* Unset the ith bit.  */
static inline void bitset_container_unset(bitset_container_t *bitset,
                                          uint16_t pos) {
    uint64_t shift = 6;
    uint64_t offset;
    uint64_t p = pos;
    ASM_SHIFT_RIGHT(p, shift, offset);
    uint64_t load = bitset->words[offset];
    ASM_CLEAR_BIT_DEC_WAS_SET(load, p, bitset->cardinality);
    bitset->words[offset] = load;
}

/* Add `pos' to `bitset'. Returns true if `pos' was not present. Might be slower
 * than bitset_container_set.  */
static inline bool bitset_container_add(bitset_container_t *bitset,
                                        uint16_t pos) {
    uint64_t shift = 6;
    uint64_t offset;
    uint64_t p = pos;
    ASM_SHIFT_RIGHT(p, shift, offset);
    uint64_t load = bitset->words[offset];
    // could be possibly slightly further optimized
    const int32_t oldcard = bitset->cardinality;
    ASM_SET_BIT_INC_WAS_CLEAR(load, p, bitset->cardinality);
    bitset->words[offset] = load;
    return bitset->cardinality - oldcard;
}

/* Remove `pos' from `bitset'. Returns true if `pos' was present.  Might be
 * slower than bitset_container_unset.  */
static inline bool bitset_container_remove(bitset_container_t *bitset,
                                           uint16_t pos) {
    uint64_t shift = 6;
    uint64_t offset;
    uint64_t p = pos;
    ASM_SHIFT_RIGHT(p, shift, offset);
    uint64_t load = bitset->words[offset];
    // could be possibly slightly further optimized
    const int32_t oldcard = bitset->cardinality;
    ASM_CLEAR_BIT_DEC_WAS_SET(load, p, bitset->cardinality);
    bitset->words[offset] = load;
    return oldcard - bitset->cardinality;
}

/* Get the value of the ith bit.  */
static inline bool bitset_container_get(const bitset_container_t *bitset,
                                 uint16_t pos) {
    uint64_t word = bitset->words[pos >> 6];
    const uint64_t p = pos;
    ASM_INPLACESHIFT_RIGHT(word, p);
    return word & 1;
}

#else

/* Set the ith bit.  */
static inline void bitset_container_set(bitset_container_t *bitset,
                                        uint16_t pos) {
    const uint64_t old_word = bitset->words[pos >> 6];
    const int index = pos & 63;
    const uint64_t new_word = old_word | (UINT64_C(1) << index);
    bitset->cardinality += (uint32_t)((old_word ^ new_word) >> index);
    bitset->words[pos >> 6] = new_word;
}

/* Unset the ith bit.  */
static inline void bitset_container_unset(bitset_container_t *bitset,
                                          uint16_t pos) {
    const uint64_t old_word = bitset->words[pos >> 6];
    const int index = pos & 63;
    const uint64_t new_word = old_word & (~(UINT64_C(1) << index));
    bitset->cardinality -= (uint32_t)((old_word ^ new_word) >> index);
    bitset->words[pos >> 6] = new_word;
}

/* Add `pos' to `bitset'. Returns true if `pos' was not present. Might be slower
 * than bitset_container_set.  */
static inline bool bitset_container_add(bitset_container_t *bitset,
                                        uint16_t pos) {
    const uint64_t old_word = bitset->words[pos >> 6];
    const int index = pos & 63;
    const uint64_t new_word = old_word | (UINT64_C(1) << index);
    const uint64_t increment = (old_word ^ new_word) >> index;
    bitset->cardinality += (uint32_t)increment;
    bitset->words[pos >> 6] = new_word;
    return increment > 0;
}

/* Remove `pos' from `bitset'. Returns true if `pos' was present.  Might be
 * slower than bitset_container_unset.  */
static inline bool bitset_container_remove(bitset_container_t *bitset,
                                           uint16_t pos) {
    const uint64_t old_word = bitset->words[pos >> 6];
    const int index = pos & 63;
    const uint64_t new_word = old_word & (~(UINT64_C(1) << index));
    const uint64_t increment = (old_word ^ new_word) >> index;
    bitset->cardinality -= (uint32_t)increment;
    bitset->words[pos >> 6] = new_word;
    return increment > 0;
}

/* Get the value of the ith bit.  */
static inline bool bitset_container_get(const bitset_container_t *bitset,
                                 uint16_t pos) {
    const uint64_t word = bitset->words[pos >> 6];
    return (word >> (pos & 63)) & 1;
}

#endif

/*
* Check if all bits are set in a range of positions from pos_start (included) to
* pos_end (excluded).
*/
static inline bool bitset_container_get_range(const bitset_container_t *bitset,
                                                uint32_t pos_start, uint32_t pos_end) {

    const uint32_t start = pos_start >> 6;
    const uint32_t end = pos_end >> 6;

    const uint64_t first = ~((1ULL << (pos_start & 0x3F)) - 1);
    const uint64_t last = (1ULL << (pos_end & 0x3F)) - 1;

    if (start == end) return ((bitset->words[end] & first & last) == (first & last));
    if ((bitset->words[start] & first) != first) return false;

    if ((end < BITSET_CONTAINER_SIZE_IN_WORDS) && ((bitset->words[end] & last) != last)){

        return false;
    }

    uint32_t i; for (i = start + 1; (i < BITSET_CONTAINER_SIZE_IN_WORDS) && (i < end); ++i){

        if (bitset->words[i] != UINT64_C(0xFFFFFFFFFFFFFFFF)) return false;
    }

    return true;
}

/* Check whether `bitset' is present in `array'.  Calls bitset_container_get. */
static inline bool bitset_container_contains(const bitset_container_t *bitset,
                                      uint16_t pos) {
    return bitset_container_get(bitset, pos);
}

/*
* Check whether a range of bits from position `pos_start' (included) to `pos_end' (excluded)
* is present in `bitset'.  Calls bitset_container_get_all.
*/
static inline bool bitset_container_contains_range(const bitset_container_t *bitset,
          uint32_t pos_start, uint32_t pos_end) {
    return bitset_container_get_range(bitset, pos_start, pos_end);
}

/* Get the number of bits set */
static inline int bitset_container_cardinality(
    const bitset_container_t *bitset) {
    return bitset->cardinality;
}

/* Copy one container into another. We assume that they are distinct. */
static void bitset_container_copy(const bitset_container_t *source,
                           bitset_container_t *dest);

/*  Add all the values [min,max) at a distance k*step from min: min,
 * min+step,.... */
static void bitset_container_add_from_range(bitset_container_t *bitset, uint32_t min,
                                     uint32_t max, uint16_t step);

/* Get the number of bits set (force computation). This does not modify bitset.
 * To update the cardinality, you should do
 * bitset->cardinality =  bitset_container_compute_cardinality(bitset).*/
static int bitset_container_compute_cardinality(const bitset_container_t *bitset);

/* Get whether there is at least one bit set  (see bitset_container_empty for the reverse),
   when the cardinality is unknown, it is computed and stored in the struct */
static inline bool bitset_container_nonzero_cardinality(
    bitset_container_t *bitset) {
    // account for laziness
    if (bitset->cardinality == BITSET_UNKNOWN_CARDINALITY) {
        // could bail early instead with a nonzero result
        bitset->cardinality = bitset_container_compute_cardinality(bitset);
    }
    return bitset->cardinality > 0;
}

/* Check whether this bitset is empty (see bitset_container_nonzero_cardinality for the reverse),
 *  it never modifies the bitset struct. */
static inline bool bitset_container_empty(
    const bitset_container_t *bitset) {
  if (bitset->cardinality == BITSET_UNKNOWN_CARDINALITY) {
      int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i ++) {
          if((bitset->words[i]) != 0) return false;
      }
      return true;
  }
  return bitset->cardinality == 0;
}


/* Get whether there is at least one bit set  (see bitset_container_empty for the reverse),
   the bitset is never modified */
static inline bool bitset_container_const_nonzero_cardinality(
    const bitset_container_t *bitset) {
    return !bitset_container_empty(bitset);
}

/*
 * Check whether the two bitsets intersect
 */
static bool bitset_container_intersect(const bitset_container_t *src_1,
                                  const bitset_container_t *src_2);

/* Computes the union of bitsets `src_1' and `src_2' into `dst'  and return the
 * cardinality. */
static int bitset_container_or(const bitset_container_t *src_1,
                        const bitset_container_t *src_2,
                        bitset_container_t *dst);

/* Computes the union of bitsets `src_1' and `src_2' and return the cardinality.
 */
static int bitset_container_or_justcard(const bitset_container_t *src_1,
                                 const bitset_container_t *src_2);

/* Computes the union of bitsets `src_1' and `src_2' into `dst' and return the
 * cardinality. Same as bitset_container_or. */
static int bitset_container_union(const bitset_container_t *src_1,
                           const bitset_container_t *src_2,
                           bitset_container_t *dst);

/* Computes the union of bitsets `src_1' and `src_2'  and return the
 * cardinality. Same as bitset_container_or_justcard. */
static int bitset_container_union_justcard(const bitset_container_t *src_1,
                                    const bitset_container_t *src_2);

/* Computes the union of bitsets `src_1' and `src_2' into `dst', but does not
 * update the cardinality. Provided to optimize chained operations. */
static int bitset_container_or_nocard(const bitset_container_t *src_1,
                               const bitset_container_t *src_2,
                               bitset_container_t *dst);

/* Computes the intersection of bitsets `src_1' and `src_2' into `dst' and
 * return the cardinality. */
static int bitset_container_and(const bitset_container_t *src_1,
                         const bitset_container_t *src_2,
                         bitset_container_t *dst);

/* Computes the intersection of bitsets `src_1' and `src_2'  and return the
 * cardinality. */
static int bitset_container_and_justcard(const bitset_container_t *src_1,
                                  const bitset_container_t *src_2);

/* Computes the intersection of bitsets `src_1' and `src_2' into `dst' and
 * return the cardinality. Same as bitset_container_and. */
static int bitset_container_intersection(const bitset_container_t *src_1,
                                  const bitset_container_t *src_2,
                                  bitset_container_t *dst);

/* Computes the intersection of bitsets `src_1' and `src_2' and return the
 * cardinality. Same as bitset_container_and_justcard. */
static int bitset_container_intersection_justcard(const bitset_container_t *src_1,
                                           const bitset_container_t *src_2);

/* Computes the intersection of bitsets `src_1' and `src_2' into `dst', but does
 * not update the cardinality. Provided to optimize chained operations. */
static int bitset_container_and_nocard(const bitset_container_t *src_1,
                                const bitset_container_t *src_2,
                                bitset_container_t *dst);

/* Computes the exclusive or of bitsets `src_1' and `src_2' into `dst' and
 * return the cardinality. */
static int bitset_container_xor(const bitset_container_t *src_1,
                         const bitset_container_t *src_2,
                         bitset_container_t *dst);

/* Computes the exclusive or of bitsets `src_1' and `src_2' and return the
 * cardinality. */
static int bitset_container_xor_justcard(const bitset_container_t *src_1,
                                  const bitset_container_t *src_2);

/* Computes the exclusive or of bitsets `src_1' and `src_2' into `dst', but does
 * not update the cardinality. Provided to optimize chained operations. */
static int bitset_container_xor_nocard(const bitset_container_t *src_1,
                                const bitset_container_t *src_2,
                                bitset_container_t *dst);

/* Computes the and not of bitsets `src_1' and `src_2' into `dst' and return the
 * cardinality. */
static int bitset_container_andnot(const bitset_container_t *src_1,
                            const bitset_container_t *src_2,
                            bitset_container_t *dst);

/* Computes the and not of bitsets `src_1' and `src_2'  and return the
 * cardinality. */
static int bitset_container_andnot_justcard(const bitset_container_t *src_1,
                                     const bitset_container_t *src_2);

/* Computes the and not or of bitsets `src_1' and `src_2' into `dst', but does
 * not update the cardinality. Provided to optimize chained operations. */
static int bitset_container_andnot_nocard(const bitset_container_t *src_1,
                                   const bitset_container_t *src_2,
                                   bitset_container_t *dst);

/*
 * Write out the 16-bit integers contained in this container as a list of 32-bit
 * integers using base
 * as the starting value (it might be expected that base has zeros in its 16
 * least significant bits).
 * The function returns the number of values written.
 * The caller is responsible for allocating enough memory in out.
 * The out pointer should point to enough memory (the cardinality times 32
 * bits).
 */
static int bitset_container_to_uint32_array(uint32_t *out,
                                     const bitset_container_t *bc,
                                     uint32_t base);

/*
 * Print this container using printf (useful for debugging).
 */
static void bitset_container_printf(const bitset_container_t *v);

/*
 * Print this container using printf as a comma-separated list of 32-bit
 * integers starting at base.
 */
static void bitset_container_printf_as_uint32_array(const bitset_container_t *v,
                                             uint32_t base);

/**
 * Return the serialized size in bytes of a container.
 */
static inline int32_t bitset_container_serialized_size_in_bytes(void) {
    return BITSET_CONTAINER_SIZE_IN_WORDS * 8;
}

/**
 * Return the the number of runs.
 */
static int bitset_container_number_of_runs(bitset_container_t *bc);

static bool bitset_container_iterate(const bitset_container_t *cont, uint32_t base,
                              roaring_iterator iterator, void *ptr);
static bool bitset_container_iterate64(const bitset_container_t *cont, uint32_t base,
                                roaring_iterator64 iterator, uint64_t high_bits,
                                void *ptr);

/**
 * Writes the underlying array to buf, outputs how many bytes were written.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes written should be
 * bitset_container_size_in_bytes(container).
 */
static int32_t bitset_container_write(const bitset_container_t *container, char *buf);

/**
 * Reads the instance from buf, outputs how many bytes were read.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes read should be bitset_container_size_in_bytes(container).
 * You need to provide the (known) cardinality.
 */
static int32_t bitset_container_read(int32_t cardinality,
                              bitset_container_t *container, const char *buf);
/**
 * Return the serialized size in bytes of a container (see
 * bitset_container_write).
 * This is meant to be compatible with the Java and Go versions of Roaring and
 * assumes
 * that the cardinality of the container is already known or can be computed.
 */
static inline int32_t bitset_container_size_in_bytes(
    const bitset_container_t *container) {
    (void)container;
    return BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);
}

/**
 * Return true if the two containers have the same content.
 */
static bool bitset_container_equals(const bitset_container_t *container1,
                             const bitset_container_t *container2);

/**
* Return true if container1 is a subset of container2.
*/
static bool bitset_container_is_subset(const bitset_container_t *container1,
                                const bitset_container_t *container2);

/**
 * If the element of given rank is in this container, supposing that the first
 * element has rank start_rank, then the function returns true and sets element
 * accordingly.
 * Otherwise, it returns false and update start_rank.
 */
static bool bitset_container_select(const bitset_container_t *container,
                             uint32_t *start_rank, uint32_t rank,
                             uint32_t *element);

/* Returns the smallest value (assumes not empty) */
static uint16_t bitset_container_minimum(const bitset_container_t *container);

/* Returns the largest value (assumes not empty) */
static uint16_t bitset_container_maximum(const bitset_container_t *container);

/* Returns the number of values equal or smaller than x */
static int bitset_container_rank(const bitset_container_t *container, uint16_t x);

/* Returns the index of the first value equal or larger than x, or -1 */
static int bitset_container_index_equalorlarger(const bitset_container_t *container, uint16_t x);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_BITSET_H_ */
/* end file include/roaring/containers/bitset.h */
/* begin file include/roaring/containers/run.h */
/*
 * run.h
 *
 */

#ifndef INCLUDE_CONTAINERS_RUN_H_
#define INCLUDE_CONTAINERS_RUN_H_

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>



#ifdef __cplusplus
extern "C" { namespace roaring {

// Note: in pure C++ code, you should avoid putting `using` in header files
using api::roaring_iterator;
using api::roaring_iterator64;

namespace internal {
#endif

/* struct rle16_s - run length pair
 *
 * @value:  start position of the run
 * @length: length of the run is `length + 1`
 *
 * An RLE pair {v, l} would represent the integers between the interval
 * [v, v+l+1], e.g. {3, 2} = [3, 4, 5].
 */
struct rle16_s {
    uint16_t value;
    uint16_t length;
};

typedef struct rle16_s rle16_t;

#ifdef __cplusplus
    #define MAKE_RLE16(val,len) \
        {(uint16_t)(val), (uint16_t)(len)}  // no tagged structs until c++20
#else
    #define MAKE_RLE16(val,len) \
        (rle16_t){.value = (uint16_t)(val), .length = (uint16_t)(len)}
#endif

/* struct run_container_s - run container bitmap
 *
 * @n_runs:   number of rle_t pairs in `runs`.
 * @capacity: capacity in rle_t pairs `runs` can hold.
 * @runs:     pairs of rle_t.
 */
STRUCT_CONTAINER(run_container_s) {
    int32_t n_runs;
    int32_t capacity;
    rle16_t *runs;
};

typedef struct run_container_s run_container_t;

#define CAST_run(c)         CAST(run_container_t *, c)  // safer downcast
#define const_CAST_run(c)   CAST(const run_container_t *, c)
#define movable_CAST_run(c) movable_CAST(run_container_t **, c)

/* Create a new run container. Return NULL in case of failure. */
static run_container_t *run_container_create(void);

/* Create a new run container with given capacity. Return NULL in case of
 * failure. */
static run_container_t *run_container_create_given_capacity(int32_t size);

/*
 * Shrink the capacity to the actual size, return the number of bytes saved.
 */
static int run_container_shrink_to_fit(run_container_t *src);

/* Free memory owned by `run'. */
static void run_container_free(run_container_t *run);

/* Duplicate container */
static run_container_t *run_container_clone(const run_container_t *src);

/*
 * Effectively deletes the value at index index, repacking data.
 */
static inline void recoverRoomAtIndex(run_container_t *run, uint16_t index) {
    memmove(run->runs + index, run->runs + (1 + index),
            (run->n_runs - index - 1) * sizeof(rle16_t));
    run->n_runs--;
}

/**
 * Good old binary search through rle data
 */
static inline int32_t interleavedBinarySearch(const rle16_t *array, int32_t lenarray,
                                       uint16_t ikey) {
    int32_t low = 0;
    int32_t high = lenarray - 1;
    while (low <= high) {
        int32_t middleIndex = (low + high) >> 1;
        uint16_t middleValue = array[middleIndex].value;
        if (middleValue < ikey) {
            low = middleIndex + 1;
        } else if (middleValue > ikey) {
            high = middleIndex - 1;
        } else {
            return middleIndex;
        }
    }
    return -(low + 1);
}

/*
 * Returns index of the run which contains $ikey
 */
static inline int32_t rle16_find_run(const rle16_t *array, int32_t lenarray,
                                     uint16_t ikey) {
    int32_t low = 0;
    int32_t high = lenarray - 1;
    while (low <= high) {
        int32_t middleIndex = (low + high) >> 1;
        uint16_t min = array[middleIndex].value;
        uint16_t max = array[middleIndex].value + array[middleIndex].length;
        if (ikey > max) {
            low = middleIndex + 1;
        } else if (ikey < min) {
            high = middleIndex - 1;
        } else {
            return middleIndex;
        }
    }
    return -(low + 1);
}


/**
 * Returns number of runs which can'be be merged with the key because they
 * are less than the key.
 * Note that [5,6,7,8] can be merged with the key 9 and won't be counted.
 */
static inline int32_t rle16_count_less(const rle16_t* array, int32_t lenarray,
                                       uint16_t key) {
    if (lenarray == 0) return 0;
    int32_t low = 0;
    int32_t high = lenarray - 1;
    while (low <= high) {
        int32_t middleIndex = (low + high) >> 1;
        uint16_t min_value = array[middleIndex].value;
        uint16_t max_value = array[middleIndex].value + array[middleIndex].length;
        if (max_value + UINT32_C(1) < key) { // uint32 arithmetic
            low = middleIndex + 1;
        } else if (key < min_value) {
            high = middleIndex - 1;
        } else {
            return middleIndex;
        }
    }
    return low;
}

static inline int32_t rle16_count_greater(const rle16_t* array, int32_t lenarray,
                                          uint16_t key) {
    if (lenarray == 0) return 0;
    int32_t low = 0;
    int32_t high = lenarray - 1;
    while (low <= high) {
        int32_t middleIndex = (low + high) >> 1;
        uint16_t min_value = array[middleIndex].value;
        uint16_t max_value = array[middleIndex].value + array[middleIndex].length;
        if (max_value < key) {
            low = middleIndex + 1;
        } else if (key + UINT32_C(1) < min_value) { // uint32 arithmetic
            high = middleIndex - 1;
        } else {
            return lenarray - (middleIndex + 1);
        }
    }
    return lenarray - low;
}

/**
 * increase capacity to at least min. Whether the
 * existing data needs to be copied over depends on copy. If "copy" is false,
 * then the new content will be uninitialized, otherwise a copy is made.
 */
static void run_container_grow(run_container_t *run, int32_t min, bool copy);

/**
 * Moves the data so that we can write data at index
 */
static inline void makeRoomAtIndex(run_container_t *run, uint16_t index) {
    /* This function calls realloc + memmove sequentially to move by one index.
     * Potentially copying twice the array.
     */
    if (run->n_runs + 1 > run->capacity)
        run_container_grow(run, run->n_runs + 1, true);
    memmove(run->runs + 1 + index, run->runs + index,
            (run->n_runs - index) * sizeof(rle16_t));
    run->n_runs++;
}

/* Add `pos' to `run'. Returns true if `pos' was not present. */
static bool run_container_add(run_container_t *run, uint16_t pos);

/* Remove `pos' from `run'. Returns true if `pos' was present. */
static inline bool run_container_remove(run_container_t *run, uint16_t pos) {
    int32_t index = interleavedBinarySearch(run->runs, run->n_runs, pos);
    if (index >= 0) {
        int32_t le = run->runs[index].length;
        if (le == 0) {
            recoverRoomAtIndex(run, (uint16_t)index);
        } else {
            run->runs[index].value++;
            run->runs[index].length--;
        }
        return true;
    }
    index = -index - 2;  // points to preceding value, possibly -1
    if (index >= 0) {    // possible match
        int32_t offset = pos - run->runs[index].value;
        int32_t le = run->runs[index].length;
        if (offset < le) {
            // need to break in two
            run->runs[index].length = (uint16_t)(offset - 1);
            // need to insert
            uint16_t newvalue = pos + 1;
            int32_t newlength = le - offset - 1;
            makeRoomAtIndex(run, (uint16_t)(index + 1));
            run->runs[index + 1].value = newvalue;
            run->runs[index + 1].length = (uint16_t)newlength;
            return true;

        } else if (offset == le) {
            run->runs[index].length--;
            return true;
        }
    }
    // no match
    return false;
}

/* Check whether `pos' is present in `run'.  */
static inline bool run_container_contains(const run_container_t *run, uint16_t pos) {
    int32_t index = interleavedBinarySearch(run->runs, run->n_runs, pos);
    if (index >= 0) return true;
    index = -index - 2;  // points to preceding value, possibly -1
    if (index != -1) {   // possible match
        int32_t offset = pos - run->runs[index].value;
        int32_t le = run->runs[index].length;
        if (offset <= le) return true;
    }
    return false;
}

/*
* Check whether all positions in a range of positions from pos_start (included)
* to pos_end (excluded) is present in `run'.
*/
static inline bool run_container_contains_range(const run_container_t *run,
                                                uint32_t pos_start, uint32_t pos_end) {
    uint32_t count = 0;
    int32_t index = interleavedBinarySearch(run->runs, run->n_runs, pos_start);
    if (index < 0) {
        index = -index - 2;
        if ((index == -1) || ((pos_start - run->runs[index].value) > run->runs[index].length)){
            return false;
        }
    }
    int32_t i; for (i = index; i < run->n_runs; ++i) {
        const uint32_t stop = run->runs[i].value + run->runs[i].length;
        if (run->runs[i].value >= pos_end) break;
        if (stop >= pos_end) {
            count += (((pos_end - run->runs[i].value) > 0) ? (pos_end - run->runs[i].value) : 0);
            break;
        }
        const uint32_t min = (stop - pos_start) > 0 ? (stop - pos_start) : 0;
        count += (min < run->runs[i].length) ? min : run->runs[i].length;
    }
    return count >= (pos_end - pos_start - 1);
}

/* Get the cardinality of `run'. Requires an actual computation. */
static int run_container_cardinality(const run_container_t *run);

/* Card > 0?, see run_container_empty for the reverse */
static inline bool run_container_nonzero_cardinality(
    const run_container_t *run) {
    return run->n_runs > 0;  // runs never empty
}

/* Card == 0?, see run_container_nonzero_cardinality for the reverse */
static inline bool run_container_empty(
    const run_container_t *run) {
    return run->n_runs == 0;  // runs never empty
}



/* Copy one container into another. We assume that they are distinct. */
static void run_container_copy(const run_container_t *src, run_container_t *dst);

/* Set the cardinality to zero (does not release memory). */
static inline void run_container_clear(run_container_t *run) {
    run->n_runs = 0;
}

/**
 * Append run described by vl to the run container, possibly merging.
 * It is assumed that the run would be inserted at the end of the container, no
 * check is made.
 * It is assumed that the run container has the necessary capacity: caller is
 * responsible for checking memory capacity.
 *
 *
 * This is not a safe function, it is meant for performance: use with care.
 */
static inline void run_container_append(run_container_t *run, rle16_t vl,
                                        rle16_t *previousrl) {
    const uint32_t previousend = previousrl->value + previousrl->length;
    if (vl.value > previousend + 1) {  // we add a new one
        run->runs[run->n_runs] = vl;
        run->n_runs++;
        *previousrl = vl;
    } else {
        uint32_t newend = vl.value + vl.length + UINT32_C(1);
        if (newend > previousend) {  // we merge
            previousrl->length = (uint16_t)(newend - 1 - previousrl->value);
            run->runs[run->n_runs - 1] = *previousrl;
        }
    }
}

/**
 * Like run_container_append but it is assumed that the content of run is empty.
 */
static inline rle16_t run_container_append_first(run_container_t *run,
                                                 rle16_t vl) {
    run->runs[run->n_runs] = vl;
    run->n_runs++;
    return vl;
}

/**
 * append a single value  given by val to the run container, possibly merging.
 * It is assumed that the value would be inserted at the end of the container,
 * no check is made.
 * It is assumed that the run container has the necessary capacity: caller is
 * responsible for checking memory capacity.
 *
 * This is not a safe function, it is meant for performance: use with care.
 */
static inline void run_container_append_value(run_container_t *run,
                                              uint16_t val,
                                              rle16_t *previousrl) {
    const uint32_t previousend = previousrl->value + previousrl->length;
    if (val > previousend + 1) {  // we add a new one
        *previousrl = MAKE_RLE16(val, 0);
        run->runs[run->n_runs] = *previousrl;
        run->n_runs++;
    } else if (val == previousend + 1) {  // we merge
        previousrl->length++;
        run->runs[run->n_runs - 1] = *previousrl;
    }
}

/**
 * Like run_container_append_value but it is assumed that the content of run is
 * empty.
 */
static inline rle16_t run_container_append_value_first(run_container_t *run,
                                                       uint16_t val) {
    rle16_t newrle = MAKE_RLE16(val, 0);
    run->runs[run->n_runs] = newrle;
    run->n_runs++;
    return newrle;
}

/* Check whether the container spans the whole chunk (cardinality = 1<<16).
 * This check can be done in constant time (inexpensive). */
static inline bool run_container_is_full(const run_container_t *run) {
    rle16_t vl = run->runs[0];
    return (run->n_runs == 1) && (vl.value == 0) && (vl.length == 0xFFFF);
}

/* Compute the union of `src_1' and `src_2' and write the result to `dst'
 * It is assumed that `dst' is distinct from both `src_1' and `src_2'. */
static void run_container_union(const run_container_t *src_1,
                         const run_container_t *src_2, run_container_t *dst);

/* Compute the union of `src_1' and `src_2' and write the result to `src_1' */
static void run_container_union_inplace(run_container_t *src_1,
                                 const run_container_t *src_2);

/* Compute the intersection of src_1 and src_2 and write the result to
 * dst. It is assumed that dst is distinct from both src_1 and src_2. */
static void run_container_intersection(const run_container_t *src_1,
                                const run_container_t *src_2,
                                run_container_t *dst);

/* Compute the size of the intersection of src_1 and src_2 . */
static int run_container_intersection_cardinality(const run_container_t *src_1,
                                           const run_container_t *src_2);

/* Check whether src_1 and src_2 intersect. */
static bool run_container_intersect(const run_container_t *src_1,
                                const run_container_t *src_2);

/* Compute the symmetric difference of `src_1' and `src_2' and write the result
 * to `dst'
 * It is assumed that `dst' is distinct from both `src_1' and `src_2'. */
static void run_container_xor(const run_container_t *src_1,
                       const run_container_t *src_2, run_container_t *dst);

/*
 * Write out the 16-bit integers contained in this container as a list of 32-bit
 * integers using base
 * as the starting value (it might be expected that base has zeros in its 16
 * least significant bits).
 * The function returns the number of values written.
 * The caller is responsible for allocating enough memory in out.
 */
static int run_container_to_uint32_array(void *vout, const run_container_t *cont,
                                  uint32_t base);

/*
 * Print this container using printf (useful for debugging).
 */
static void run_container_printf(const run_container_t *v);

/*
 * Print this container using printf as a comma-separated list of 32-bit
 * integers starting at base.
 */
static void run_container_printf_as_uint32_array(const run_container_t *v,
                                          uint32_t base);

/**
 * Return the serialized size in bytes of a container having "num_runs" runs.
 */
static inline int32_t run_container_serialized_size_in_bytes(int32_t num_runs) {
    return sizeof(uint16_t) +
           sizeof(rle16_t) * num_runs;  // each run requires 2 2-byte entries.
}

static bool run_container_iterate(const run_container_t *cont, uint32_t base,
                           roaring_iterator iterator, void *ptr);
static bool run_container_iterate64(const run_container_t *cont, uint32_t base,
                             roaring_iterator64 iterator, uint64_t high_bits,
                             void *ptr);

/**
 * Writes the underlying array to buf, outputs how many bytes were written.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes written should be run_container_size_in_bytes(container).
 */
static int32_t run_container_write(const run_container_t *container, char *buf);

/**
 * Reads the instance from buf, outputs how many bytes were read.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes read should be bitset_container_size_in_bytes(container).
 * The cardinality parameter is provided for consistency with other containers,
 * but
 * it might be effectively ignored..
 */
static int32_t run_container_read(int32_t cardinality, run_container_t *container,
                           const char *buf);

/**
 * Return the serialized size in bytes of a container (see run_container_write).
 * This is meant to be compatible with the Java and Go versions of Roaring.
 */
static inline int32_t run_container_size_in_bytes(
    const run_container_t *container) {
    return run_container_serialized_size_in_bytes(container->n_runs);
}

/**
 * Return true if the two containers have the same content.
 */
static inline bool run_container_equals(const run_container_t *container1,
                          const run_container_t *container2) {
    if (container1->n_runs != container2->n_runs) {
        return false;
    }
    return memequals(container1->runs, container2->runs,
                     container1->n_runs * sizeof(rle16_t));
}

/**
* Return true if container1 is a subset of container2.
*/
static bool run_container_is_subset(const run_container_t *container1,
                             const run_container_t *container2);

/**
 * Used in a start-finish scan that appends segments, for XOR and NOT
 */

static void run_container_smart_append_exclusive(run_container_t *src,
                                          const uint16_t start,
                                          const uint16_t length);

/**
* The new container consists of a single run [start,stop).
* It is required that stop>start, the caller is responsability for this check.
* It is required that stop <= (1<<16), the caller is responsability for this check.
* The cardinality of the created container is stop - start.
* Returns NULL on failure
*/
static inline run_container_t *run_container_create_range(uint32_t start,
                                                          uint32_t stop) {
    run_container_t *rc = run_container_create_given_capacity(1);
    if (rc) {
        rle16_t r;
        r.value = (uint16_t)start;
        r.length = (uint16_t)(stop - start - 1);
        run_container_append_first(rc, r);
    }
    return rc;
}

/**
 * If the element of given rank is in this container, supposing that the first
 * element has rank start_rank, then the function returns true and sets element
 * accordingly.
 * Otherwise, it returns false and update start_rank.
 */
static bool run_container_select(const run_container_t *container,
                          uint32_t *start_rank, uint32_t rank,
                          uint32_t *element);

/* Compute the difference of src_1 and src_2 and write the result to
 * dst. It is assumed that dst is distinct from both src_1 and src_2. */

static void run_container_andnot(const run_container_t *src_1,
                          const run_container_t *src_2, run_container_t *dst);

/* Returns the smallest value (assumes not empty) */
static inline uint16_t run_container_minimum(const run_container_t *run) {
    if (run->n_runs == 0) return 0;
    return run->runs[0].value;
}

/* Returns the largest value (assumes not empty) */
static inline uint16_t run_container_maximum(const run_container_t *run) {
    if (run->n_runs == 0) return 0;
    return run->runs[run->n_runs - 1].value + run->runs[run->n_runs - 1].length;
}

/* Returns the number of values equal or smaller than x */
static int run_container_rank(const run_container_t *arr, uint16_t x);

/* Returns the index of the first run containing a value at least as large as x, or -1 */
static inline int run_container_index_equalorlarger(const run_container_t *arr, uint16_t x) {
    int32_t index = interleavedBinarySearch(arr->runs, arr->n_runs, x);
    if (index >= 0) return index;
    index = -index - 2;  // points to preceding run, possibly -1
    if (index != -1) {   // possible match
        int32_t offset = x - arr->runs[index].value;
        int32_t le = arr->runs[index].length;
        if (offset <= le) return index;
    }
    index += 1;
    if(index  < arr->n_runs) {
      return index;
    }
    return -1;
}

/*
 * Add all values in range [min, max] using hint.
 */
static inline void run_container_add_range_nruns(run_container_t* run,
                                                 uint32_t min, uint32_t max,
                                                 int32_t nruns_less,
                                                 int32_t nruns_greater) {
    int32_t nruns_common = run->n_runs - nruns_less - nruns_greater;
    if (nruns_common == 0) {
        makeRoomAtIndex(run, nruns_less);
        run->runs[nruns_less].value = min;
        run->runs[nruns_less].length = max - min;
    } else {
        uint32_t common_min = run->runs[nruns_less].value;
        uint32_t common_max = run->runs[nruns_less + nruns_common - 1].value +
                              run->runs[nruns_less + nruns_common - 1].length;
        uint32_t result_min = (common_min < min) ? common_min : min;
        uint32_t result_max = (common_max > max) ? common_max : max;

        run->runs[nruns_less].value = result_min;
        run->runs[nruns_less].length = result_max - result_min;

        memmove(&(run->runs[nruns_less + 1]),
                &(run->runs[run->n_runs - nruns_greater]),
                nruns_greater*sizeof(rle16_t));
        run->n_runs = nruns_less + 1 + nruns_greater;
    }
}

/**
 * Add all values in range [min, max]
 */
static inline void run_container_add_range(run_container_t* run,
                                           uint32_t min, uint32_t max) {
    int32_t nruns_greater = rle16_count_greater(run->runs, run->n_runs, max);
    int32_t nruns_less = rle16_count_less(run->runs, run->n_runs - nruns_greater, min);
    run_container_add_range_nruns(run, min, max, nruns_less, nruns_greater);
}

/**
 * Shifts last $count elements either left (distance < 0) or right (distance > 0)
 */
static inline void run_container_shift_tail(run_container_t* run,
                                            int32_t count, int32_t distance) {
    if (distance > 0) {
        if (run->capacity < count+distance) {
            run_container_grow(run, count+distance, true);
        }
    }
    int32_t srcpos = run->n_runs - count;
    int32_t dstpos = srcpos + distance;
    memmove(&(run->runs[dstpos]), &(run->runs[srcpos]), sizeof(rle16_t) * count);
    run->n_runs += distance;
}

/**
 * Remove all elements in range [min, max]
 */
static inline void run_container_remove_range(run_container_t *run, uint32_t min, uint32_t max) {
    int32_t first = rle16_find_run(run->runs, run->n_runs, min);
    int32_t last = rle16_find_run(run->runs, run->n_runs, max);

    if (first >= 0 && min > run->runs[first].value &&
        max < ((uint32_t)run->runs[first].value + (uint32_t)run->runs[first].length)) {
        // split this run into two adjacent runs

        // right subinterval
        makeRoomAtIndex(run, first+1);
        run->runs[first+1].value = max + 1;
        run->runs[first+1].length = (run->runs[first].value + run->runs[first].length) - (max + 1);

        // left subinterval
        run->runs[first].length = (min - 1) - run->runs[first].value;

        return;
    }

    // update left-most partial run
    if (first >= 0) {
        if (min > run->runs[first].value) {
            run->runs[first].length = (min - 1) - run->runs[first].value;
            first++;
        }
    } else {
        first = -first-1;
    }

    // update right-most run
    if (last >= 0) {
        uint16_t run_max = run->runs[last].value + run->runs[last].length;
        if (run_max > max) {
            run->runs[last].value = max + 1;
            run->runs[last].length = run_max - (max + 1);
            last--;
        }
    } else {
        last = (-last-1) - 1;
    }

    // remove intermediate runs
    if (first <= last) {
        run_container_shift_tail(run, run->n_runs - (last+1), -(last-first+1));
    }
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_RUN_H_ */
/* end file include/roaring/containers/run.h */
/* begin file include/roaring/containers/convert.h */
/*
 * convert.h
 *
 */

#ifndef INCLUDE_CONTAINERS_CONVERT_H_
#define INCLUDE_CONTAINERS_CONVERT_H_


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Convert an array into a bitset. The input container is not freed or modified.
 */
static bitset_container_t *bitset_container_from_array(const array_container_t *arr);

/* Convert a run into a bitset. The input container is not freed or modified. */
static bitset_container_t *bitset_container_from_run(const run_container_t *arr);

/* Convert a run into an array. The input container is not freed or modified. */
static array_container_t *array_container_from_run(const run_container_t *arr);

/* Convert a bitset into an array. The input container is not freed or modified.
 */
static array_container_t *array_container_from_bitset(const bitset_container_t *bits);

/* Convert an array into a run. The input container is not freed or modified.
 */
static run_container_t *run_container_from_array(const array_container_t *c);

/* convert a run into either an array or a bitset
 * might free the container. This does not free the input run container. */
static container_t *convert_to_bitset_or_array_container(
        run_container_t *rc, int32_t card,
        uint8_t *resulttype);

/* convert containers to and from runcontainers, as is most space efficient.
 * The container might be freed. */
static container_t *convert_run_optimize(
        container_t *c, uint8_t typecode_original,
        uint8_t *typecode_after);

/* converts a run container to either an array or a bitset, IF it saves space.
 */
/* If a conversion occurs, the caller is responsible to free the original
 * container and
 * he becomes reponsible to free the new one. */
static container_t *convert_run_to_efficient_container(
        run_container_t *c, uint8_t *typecode_after);

// like convert_run_to_efficient_container but frees the old result if needed
static container_t *convert_run_to_efficient_container_and_free(
        run_container_t *c, uint8_t *typecode_after);

/**
 * Create new container which is a union of run container and
 * range [min, max]. Caller is responsible for freeing run container.
 */
static container_t *container_from_run_range(
        const run_container_t *run,
        uint32_t min, uint32_t max,
        uint8_t *typecode_after);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_CONVERT_H_ */
/* end file include/roaring/containers/convert.h */
/* begin file include/roaring/containers/mixed_equal.h */
/*
 * mixed_equal.h
 *
 */

#ifndef CONTAINERS_MIXED_EQUAL_H_
#define CONTAINERS_MIXED_EQUAL_H_


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/**
 * Return true if the two containers have the same content.
 */
static bool array_container_equal_bitset(const array_container_t* container1,
                                  const bitset_container_t* container2);

/**
 * Return true if the two containers have the same content.
 */
static bool run_container_equals_array(const run_container_t* container1,
                                const array_container_t* container2);
/**
 * Return true if the two containers have the same content.
 */
static bool run_container_equals_bitset(const run_container_t* container1,
                                 const bitset_container_t* container2);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* CONTAINERS_MIXED_EQUAL_H_ */
/* end file include/roaring/containers/mixed_equal.h */
/* begin file include/roaring/containers/mixed_subset.h */
/*
 * mixed_subset.h
 *
 */

#ifndef CONTAINERS_MIXED_SUBSET_H_
#define CONTAINERS_MIXED_SUBSET_H_


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/**
 * Return true if container1 is a subset of container2.
 */
static bool array_container_is_subset_bitset(const array_container_t* container1,
                                      const bitset_container_t* container2);

/**
* Return true if container1 is a subset of container2.
 */
static bool run_container_is_subset_array(const run_container_t* container1,
                                   const array_container_t* container2);

/**
* Return true if container1 is a subset of container2.
 */
static bool array_container_is_subset_run(const array_container_t* container1,
                                   const run_container_t* container2);

/**
* Return true if container1 is a subset of container2.
 */
static bool run_container_is_subset_bitset(const run_container_t* container1,
                                    const bitset_container_t* container2);

/**
* Return true if container1 is a subset of container2.
*/
static bool bitset_container_is_subset_run(const bitset_container_t* container1,
                                    const run_container_t* container2);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* CONTAINERS_MIXED_SUBSET_H_ */
/* end file include/roaring/containers/mixed_subset.h */
/* begin file include/roaring/containers/mixed_andnot.h */
/*
 * mixed_andnot.h
 */
#ifndef INCLUDE_CONTAINERS_MIXED_ANDNOT_H_
#define INCLUDE_CONTAINERS_MIXED_ANDNOT_H_


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst, a valid array container that could be the same as dst.*/
static void array_bitset_container_andnot(const array_container_t *src_1,
                                   const bitset_container_t *src_2,
                                   array_container_t *dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * src_1 */

static void array_bitset_container_iandnot(array_container_t *src_1,
                                    const bitset_container_t *src_2);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst, which does not initially have a valid container.
 * Return true for a bitset result; false for array
 */

static bool bitset_array_container_andnot(
        const bitset_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_array_container_iandnot(
        bitset_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_andnot(
        const run_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_iandnot(
        run_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset").  dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool bitset_run_container_andnot(
        const bitset_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_run_container_iandnot(
        bitset_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/* dst does not indicate a valid container initially.  Eventually it
 * can become any type of container.
 */

static int run_array_container_andnot(
        const run_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static int run_array_container_iandnot(
        run_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* dst must be a valid array container, allowed to be src_1 */

static void array_run_container_andnot(const array_container_t *src_1,
                                const run_container_t *src_2,
                                array_container_t *dst);

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static void array_run_container_iandnot(array_container_t *src_1,
                                 const run_container_t *src_2);

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int run_run_container_andnot(
        const run_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static int run_run_container_iandnot(
        run_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/*
 * dst is a valid array container and may be the same as src_1
 */

static void array_array_container_andnot(const array_container_t *src_1,
                                  const array_container_t *src_2,
                                  array_container_t *dst);

/* inplace array-array andnot will always be able to reuse the space of
 * src_1 */
static void array_array_container_iandnot(array_container_t *src_1,
                                   const array_container_t *src_2);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially). Return value is
 * "dst is a bitset"
 */

static bool bitset_bitset_container_andnot(
        const bitset_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_bitset_container_iandnot(
        bitset_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif
/* end file include/roaring/containers/mixed_andnot.h */
/* begin file include/roaring/containers/mixed_intersection.h */
/*
 * mixed_intersection.h
 *
 */

#ifndef INCLUDE_CONTAINERS_MIXED_INTERSECTION_H_
#define INCLUDE_CONTAINERS_MIXED_INTERSECTION_H_

/* These functions appear to exclude cases where the
 * inputs have the same type and the output is guaranteed
 * to have the same type as the inputs.  Eg, array intersection
 */


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the intersection of src_1 and src_2 and write the result to
 * dst. It is allowed for dst to be equal to src_1. We assume that dst is a
 * valid container. */
static void array_bitset_container_intersection(const array_container_t *src_1,
                                         const bitset_container_t *src_2,
                                         array_container_t *dst);

/* Compute the size of the intersection of src_1 and src_2. */
static int array_bitset_container_intersection_cardinality(
    const array_container_t *src_1, const bitset_container_t *src_2);



/* Checking whether src_1 and src_2 intersect. */
static bool array_bitset_container_intersect(const array_container_t *src_1,
                                         const bitset_container_t *src_2);

/*
 * Compute the intersection between src_1 and src_2 and write the result
 * to *dst. If the return function is true, the result is a bitset_container_t
 * otherwise is a array_container_t. We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static bool bitset_bitset_container_intersection(const bitset_container_t *src_1,
                                          const bitset_container_t *src_2,
                                          container_t **dst);

/* Compute the intersection between src_1 and src_2 and write the result to
 * dst. It is allowed for dst to be equal to src_1. We assume that dst is a
 * valid container. */
static void array_run_container_intersection(const array_container_t *src_1,
                                      const run_container_t *src_2,
                                      array_container_t *dst);

/* Compute the intersection between src_1 and src_2 and write the result to
 * *dst. If the result is true then the result is a bitset_container_t
 * otherwise is a array_container_t.
 * If *dst == src_2, then an in-place intersection is attempted
 **/
static bool run_bitset_container_intersection(const run_container_t *src_1,
                                       const bitset_container_t *src_2,
                                       container_t **dst);

/* Compute the size of the intersection between src_1 and src_2 . */
static int array_run_container_intersection_cardinality(const array_container_t *src_1,
                                                 const run_container_t *src_2);

/* Compute the size of the intersection  between src_1 and src_2
 **/
static int run_bitset_container_intersection_cardinality(const run_container_t *src_1,
                                       const bitset_container_t *src_2);


/* Check that src_1 and src_2 intersect. */
static bool array_run_container_intersect(const array_container_t *src_1,
                                      const run_container_t *src_2);

/* Check that src_1 and src_2 intersect.
 **/
static bool run_bitset_container_intersect(const run_container_t *src_1,
                                       const bitset_container_t *src_2);

/*
 * Same as bitset_bitset_container_intersection except that if the output is to
 * be a
 * bitset_container_t, then src_1 is modified and no allocation is made.
 * If the output is to be an array_container_t, then caller is responsible
 * to free the container.
 * In all cases, the result is in *dst.
 */
static bool bitset_bitset_container_intersection_inplace(
    bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_MIXED_INTERSECTION_H_ */
/* end file include/roaring/containers/mixed_intersection.h */
/* begin file include/roaring/containers/mixed_negation.h */
/*
 * mixed_negation.h
 *
 */

#ifndef INCLUDE_CONTAINERS_MIXED_NEGATION_H_
#define INCLUDE_CONTAINERS_MIXED_NEGATION_H_


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Negation across the entire range of the container.
 * Compute the  negation of src  and write the result
 * to *dst. The complement of a
 * sufficiently sparse set will always be dense and a hence a bitmap
 * We assume that dst is pre-allocated and a valid bitset container
 * There can be no in-place version.
 */
static void array_container_negation(const array_container_t *src,
                              bitset_container_t *dst);

/* Negation across the entire range of the container
 * Compute the  negation of src  and write the result
 * to *dst.  A true return value indicates a bitset result,
 * otherwise the result is an array container.
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static bool bitset_container_negation(
        const bitset_container_t *src,
        container_t **dst);

/* inplace version */
/*
 * Same as bitset_container_negation except that if the output is to
 * be a
 * bitset_container_t, then src is modified and no allocation is made.
 * If the output is to be an array_container_t, then caller is responsible
 * to free the container.
 * In all cases, the result is in *dst.
 */
static bool bitset_container_negation_inplace(
        bitset_container_t *src,
        container_t **dst);

/* Negation across the entire range of container
 * Compute the  negation of src  and write the result
 * to *dst.
 * Return values are the *_TYPECODES as defined * in containers.h
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static int run_container_negation(const run_container_t *src, container_t **dst);

/*
 * Same as run_container_negation except that if the output is to
 * be a
 * run_container_t, and has the capacity to hold the result,
 * then src is modified and no allocation is made.
 * In all cases, the result is in *dst.
 */
static int run_container_negation_inplace(run_container_t *src, container_t **dst);

/* Negation across a range of the container.
 * Compute the  negation of src  and write the result
 * to *dst. Returns true if the result is a bitset container
 * and false for an array container.  *dst is not preallocated.
 */
static bool array_container_negation_range(
        const array_container_t *src,
        const int range_start, const int range_end,
        container_t **dst);

/* Even when the result would fit, it is unclear how to make an
 * inplace version without inefficient copying.  Thus this routine
 * may be a wrapper for the non-in-place version
 */
static bool array_container_negation_range_inplace(
        array_container_t *src,
        const int range_start, const int range_end,
        container_t **dst);

/* Negation across a range of the container
 * Compute the  negation of src  and write the result
 * to *dst.  A true return value indicates a bitset result,
 * otherwise the result is an array container.
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static bool bitset_container_negation_range(
        const bitset_container_t *src,
        const int range_start, const int range_end,
        container_t **dst);

/* inplace version */
/*
 * Same as bitset_container_negation except that if the output is to
 * be a
 * bitset_container_t, then src is modified and no allocation is made.
 * If the output is to be an array_container_t, then caller is responsible
 * to free the container.
 * In all cases, the result is in *dst.
 */
static bool bitset_container_negation_range_inplace(
        bitset_container_t *src,
        const int range_start, const int range_end,
        container_t **dst);

/* Negation across a range of container
 * Compute the  negation of src  and write the result
 * to *dst.  Return values are the *_TYPECODES as defined * in containers.h
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static int run_container_negation_range(
        const run_container_t *src,
        const int range_start, const int range_end,
        container_t **dst);

/*
 * Same as run_container_negation except that if the output is to
 * be a
 * run_container_t, and has the capacity to hold the result,
 * then src is modified and no allocation is made.
 * In all cases, the result is in *dst.
 */
static int run_container_negation_range_inplace(
        run_container_t *src,
        const int range_start, const int range_end,
        container_t **dst);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_MIXED_NEGATION_H_ */
/* end file include/roaring/containers/mixed_negation.h */
/* begin file include/roaring/containers/mixed_union.h */
/*
 * mixed_intersection.h
 *
 */

#ifndef INCLUDE_CONTAINERS_MIXED_UNION_H_
#define INCLUDE_CONTAINERS_MIXED_UNION_H_

/* These functions appear to exclude cases where the
 * inputs have the same type and the output is guaranteed
 * to have the same type as the inputs.  Eg, bitset unions
 */


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the union of src_1 and src_2 and write the result to
 * dst. It is allowed for src_2 to be dst.   */
static void array_bitset_container_union(const array_container_t *src_1,
                                  const bitset_container_t *src_2,
                                  bitset_container_t *dst);

/* Compute the union of src_1 and src_2 and write the result to
 * dst. It is allowed for src_2 to be dst.  This version does not
 * update the cardinality of dst (it is set to BITSET_UNKNOWN_CARDINALITY). */
static void array_bitset_container_lazy_union(const array_container_t *src_1,
                                       const bitset_container_t *src_2,
                                       bitset_container_t *dst);

/*
 * Compute the union between src_1 and src_2 and write the result
 * to *dst. If the return function is true, the result is a bitset_container_t
 * otherwise is a array_container_t. We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static bool array_array_container_union(
        const array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/*
 * Compute the union between src_1 and src_2 and write the result
 * to *dst if it cannot be written to src_1. If the return function is true,
 * the result is a bitset_container_t
 * otherwise is a array_container_t. When the result is an array_container_t, it
 * it either written to src_1 (if *dst is null) or to *dst.
 * If the result is a bitset_container_t and *dst is null, then there was a failure.
 */
static bool array_array_container_inplace_union(
        array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/*
 * Same as array_array_container_union except that it will more eagerly produce
 * a bitset.
 */
static bool array_array_container_lazy_union(
        const array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/*
 * Same as array_array_container_inplace_union except that it will more eagerly produce
 * a bitset.
 */
static bool array_array_container_lazy_inplace_union(
        array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* Compute the union of src_1 and src_2 and write the result to
 * dst. We assume that dst is a
 * valid container. The result might need to be further converted to array or
 * bitset container,
 * the caller is responsible for the eventual conversion. */
static void array_run_container_union(const array_container_t *src_1,
                               const run_container_t *src_2,
                               run_container_t *dst);

/* Compute the union of src_1 and src_2 and write the result to
 * src2. The result might need to be further converted to array or
 * bitset container,
 * the caller is responsible for the eventual conversion. */
static void array_run_container_inplace_union(const array_container_t *src_1,
                                       run_container_t *src_2);

/* Compute the union of src_1 and src_2 and write the result to
 * dst. It is allowed for dst to be src_2.
 * If run_container_is_full(src_1) is true, you must not be calling this
 *function.
 **/
static void run_bitset_container_union(const run_container_t *src_1,
                                const bitset_container_t *src_2,
                                bitset_container_t *dst);

/* Compute the union of src_1 and src_2 and write the result to
 * dst. It is allowed for dst to be src_2.  This version does not
 * update the cardinality of dst (it is set to BITSET_UNKNOWN_CARDINALITY).
 * If run_container_is_full(src_1) is true, you must not be calling this
 * function.
 * */
static void run_bitset_container_lazy_union(const run_container_t *src_1,
                                     const bitset_container_t *src_2,
                                     bitset_container_t *dst);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif /* INCLUDE_CONTAINERS_MIXED_UNION_H_ */
/* end file include/roaring/containers/mixed_union.h */
/* begin file include/roaring/containers/mixed_xor.h */
/*
 * mixed_xor.h
 *
 */

#ifndef INCLUDE_CONTAINERS_MIXED_XOR_H_
#define INCLUDE_CONTAINERS_MIXED_XOR_H_

/* These functions appear to exclude cases where the
 * inputs have the same type and the output is guaranteed
 * to have the same type as the inputs.  Eg, bitset unions
 */

/*
 * Java implementation (as of May 2016) for array_run, run_run
 * and  bitset_run don't do anything different for inplace.
 * (They are not truly in place.)
 */



#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the xor of src_1 and src_2 and write the result to
 * dst (which has no container initially).
 * Result is true iff dst is a bitset  */
static bool array_bitset_container_xor(
        const array_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* Compute the xor of src_1 and src_2 and write the result to
 * dst. It is allowed for src_2 to be dst.  This version does not
 * update the cardinality of dst (it is set to BITSET_UNKNOWN_CARDINALITY).
 */

static void array_bitset_container_lazy_xor(const array_container_t *src_1,
                                     const bitset_container_t *src_2,
                                     bitset_container_t *dst);
/* Compute the xor of src_1 and src_2 and write the result to
 * dst (which has no container initially). Return value is
 * "dst is a bitset"
 */

static bool bitset_bitset_container_xor(
        const bitset_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* Compute the xor of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_xor(
        const run_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* lazy xor.  Dst is initialized and may be equal to src_2.
 *  Result is left as a bitset container, even if actual
 *  cardinality would dictate an array container.
 */

static void run_bitset_container_lazy_xor(const run_container_t *src_1,
                                   const bitset_container_t *src_2,
                                   bitset_container_t *dst);

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int array_run_container_xor(
        const array_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/* dst does not initially have a valid container.  Creates either
 * an array or a bitset container, indicated by return code
 */

static bool array_array_container_xor(
        const array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* dst does not initially have a valid container.  Creates either
 * an array or a bitset container, indicated by return code.
 * A bitset container will not have a valid cardinality and the
 * container type might not be correct for the actual cardinality
 */

static bool array_array_container_lazy_xor(
        const array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

/* Dst is a valid run container. (Can it be src_2? Let's say not.)
 * Leaves result as run container, even if other options are
 * smaller.
 */

static void array_run_container_lazy_xor(const array_container_t *src_1,
                                  const run_container_t *src_2,
                                  run_container_t *dst);

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int run_run_container_xor(
        const run_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/* INPLACE versions (initial implementation may not exploit all inplace
 * opportunities (if any...)
 */

/* Compute the xor of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_array_container_ixor(
        bitset_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

static bool bitset_bitset_container_ixor(
        bitset_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

static bool array_bitset_container_ixor(
        array_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

/* Compute the xor of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_ixor(
        run_container_t *src_1, const bitset_container_t *src_2,
        container_t **dst);

static bool bitset_run_container_ixor(
        bitset_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int array_run_container_ixor(
        array_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

static int run_array_container_ixor(
        run_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

static bool array_array_container_ixor(
        array_container_t *src_1, const array_container_t *src_2,
        container_t **dst);

static int run_run_container_ixor(
        run_container_t *src_1, const run_container_t *src_2,
        container_t **dst);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif
/* end file include/roaring/containers/mixed_xor.h */
/* begin file include/roaring/containers/containers.h */
#ifndef CONTAINERS_CONTAINERS_H
#define CONTAINERS_CONTAINERS_H

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

// would enum be possible or better?

/**
 * The switch case statements follow
 * BITSET_CONTAINER_TYPE -- ARRAY_CONTAINER_TYPE -- RUN_CONTAINER_TYPE
 * so it makes more sense to number them 1, 2, 3 (in the vague hope that the
 * compiler might exploit this ordering).
 */

#define BITSET_CONTAINER_TYPE 1
#define ARRAY_CONTAINER_TYPE 2
#define RUN_CONTAINER_TYPE 3
#define SHARED_CONTAINER_TYPE 4

/**
 * Macros for pairing container type codes, suitable for switch statements.
 * Use PAIR_CONTAINER_TYPES() for the switch, CONTAINER_PAIR() for the cases:
 *
 *     switch (PAIR_CONTAINER_TYPES(type1, type2)) {
 *        case CONTAINER_PAIR(BITSET,ARRAY):
 *        ...
 *     }
 */
#define PAIR_CONTAINER_TYPES(type1,type2) \
    (4 * (type1) + (type2))

#define CONTAINER_PAIR(name1,name2) \
    (4 * (name1##_CONTAINER_TYPE) + (name2##_CONTAINER_TYPE))

/**
 * A shared container is a wrapper around a container
 * with reference counting.
 */

STRUCT_CONTAINER(shared_container_s) {
    container_t *container;
    uint8_t typecode;
    uint32_t counter;  // to be managed atomically
};

typedef struct shared_container_s shared_container_t;

#define CAST_shared(c)         CAST(shared_container_t *, c)  // safer downcast
#define const_CAST_shared(c)   CAST(const shared_container_t *, c)
#define movable_CAST_shared(c) movable_CAST(shared_container_t **, c)

/*
 * With copy_on_write = true
 *  Create a new shared container if the typecode is not SHARED_CONTAINER_TYPE,
 * otherwise, increase the count
 * If copy_on_write = false, then clone.
 * Return NULL in case of failure.
 **/
static container_t *get_copy_of_container(container_t *container, uint8_t *typecode,
                                   bool copy_on_write);

/* Frees a shared container (actually decrement its counter and only frees when
 * the counter falls to zero). */
static void shared_container_free(shared_container_t *container);

/* extract a copy from the shared container, freeing the shared container if
there is just one instance left,
clone instances when the counter is higher than one
*/
static container_t *shared_container_extract_copy(shared_container_t *container,
                                           uint8_t *typecode);

/* access to container underneath */
static inline const container_t *container_unwrap_shared(
    const container_t *candidate_shared_container, uint8_t *type
){
    if (*type == SHARED_CONTAINER_TYPE) {
        *type = const_CAST_shared(candidate_shared_container)->typecode;
        assert(*type != SHARED_CONTAINER_TYPE);
        return const_CAST_shared(candidate_shared_container)->container;
    } else {
        return candidate_shared_container;
    }
}


/* access to container underneath */
static inline container_t *container_mutable_unwrap_shared(
    container_t *c, uint8_t *type
) {
    if (*type == SHARED_CONTAINER_TYPE) {  // the passed in container is shared
        *type = CAST_shared(c)->typecode;
        assert(*type != SHARED_CONTAINER_TYPE);
        return CAST_shared(c)->container;  // return the enclosed container
    } else {
        return c;  // wasn't shared, so return as-is
    }
}

/* access to container underneath and queries its type */
static inline uint8_t get_container_type(
    const container_t *c, uint8_t type
){
    if (type == SHARED_CONTAINER_TYPE) {
        return const_CAST_shared(c)->typecode;
    } else {
        return type;
    }
}

/**
 * Copies a container, requires a typecode. This allocates new memory, caller
 * is responsible for deallocation. If the container is not shared, then it is
 * physically cloned. Sharable containers are not cloneable.
 */
static container_t *container_clone(const container_t *container, uint8_t typecode);

/* access to container underneath, cloning it if needed */
static inline container_t *get_writable_copy_if_shared(
    container_t *c, uint8_t *type
){
    if (*type == SHARED_CONTAINER_TYPE) {  // shared, return enclosed container
        return shared_container_extract_copy(CAST_shared(c), type);
    } else {
        return c;  // not shared, so return as-is
    }
}

/**
 * End of shared container code
 */

static const char *container_names[] = {"bitset", "array", "run", "shared"};
static const char *shared_container_names[] = {
    "bitset (shared)", "array (shared)", "run (shared)"};

// no matter what the initial container was, convert it to a bitset
// if a new container is produced, caller responsible for freeing the previous
// one
// container should not be a shared container
static inline bitset_container_t *container_to_bitset(
    container_t *c, uint8_t typecode
){
    bitset_container_t *result = NULL;
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return CAST_bitset(c);  // nothing to do
        case ARRAY_CONTAINER_TYPE:
            result = bitset_container_from_array(CAST_array(c));
            return result;
        case RUN_CONTAINER_TYPE:
            result = bitset_container_from_run(CAST_run(c));
            return result;
        case SHARED_CONTAINER_TYPE:
            assert(false);
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

/**
 * Get the container name from the typecode
 * (unused at time of writing)
 */
static inline const char *get_container_name(uint8_t typecode) {
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return container_names[0];
        case ARRAY_CONTAINER_TYPE:
            return container_names[1];
        case RUN_CONTAINER_TYPE:
            return container_names[2];
        case SHARED_CONTAINER_TYPE:
            return container_names[3];
        default:
            assert(false);
            __builtin_unreachable();
            return "unknown";
    }
}

static inline const char *get_full_container_name(
    const container_t *c, uint8_t typecode
){
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return container_names[0];
        case ARRAY_CONTAINER_TYPE:
            return container_names[1];
        case RUN_CONTAINER_TYPE:
            return container_names[2];
        case SHARED_CONTAINER_TYPE:
            switch (const_CAST_shared(c)->typecode) {
                case BITSET_CONTAINER_TYPE:
                    return shared_container_names[0];
                case ARRAY_CONTAINER_TYPE:
                    return shared_container_names[1];
                case RUN_CONTAINER_TYPE:
                    return shared_container_names[2];
                default:
                    assert(false);
                    __builtin_unreachable();
                    return "unknown";
            }
            break;
        default:
            assert(false);
            __builtin_unreachable();
            return "unknown";
    }
    __builtin_unreachable();
    return NULL;
}

/**
 * Get the container cardinality (number of elements), requires a  typecode
 */
static inline int container_get_cardinality(
    const container_t *c, uint8_t typecode
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_cardinality(const_CAST_bitset(c));
        case ARRAY_CONTAINER_TYPE:
            return array_container_cardinality(const_CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_cardinality(const_CAST_run(c));
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}



// returns true if a container is known to be full. Note that a lazy bitset
// container
// might be full without us knowing
static inline bool container_is_full(const container_t *c, uint8_t typecode) {
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_cardinality(
                       const_CAST_bitset(c)) == (1 << 16);
        case ARRAY_CONTAINER_TYPE:
            return array_container_cardinality(
                       const_CAST_array(c)) == (1 << 16);
        case RUN_CONTAINER_TYPE:
            return run_container_is_full(const_CAST_run(c));
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

static inline int container_shrink_to_fit(
    container_t *c, uint8_t type
){
    c = container_mutable_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return 0;  // no shrinking possible
        case ARRAY_CONTAINER_TYPE:
            return array_container_shrink_to_fit(CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_shrink_to_fit(CAST_run(c));
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}


/**
 * make a container with a run of ones
 */
/* initially always use a run container, even if an array might be
 * marginally
 * smaller */
static inline container_t *container_range_of_ones(
    uint32_t range_start, uint32_t range_end,
    uint8_t *result_type
){
    assert(range_end >= range_start);
    uint64_t cardinality =  range_end - range_start + 1;
    if(cardinality <= 2) {
      *result_type = ARRAY_CONTAINER_TYPE;
      return array_container_create_range(range_start, range_end);
    } else {
      *result_type = RUN_CONTAINER_TYPE;
      return run_container_create_range(range_start, range_end);
    }
}


/*  Create a container with all the values between in [min,max) at a
    distance k*step from min. */
static inline container_t *container_from_range(
    uint8_t *type, uint32_t min,
    uint32_t max, uint16_t step
){
    if (step == 0) return NULL;  // being paranoid
    if (step == 1) {
        return container_range_of_ones(min,max,type);
        // Note: the result is not always a run (need to check the cardinality)
        //*type = RUN_CONTAINER_TYPE;
        //return run_container_create_range(min, max);
    }
    int size = (max - min + step - 1) / step;
    if (size <= DEFAULT_MAX_SIZE) {  // array container
        *type = ARRAY_CONTAINER_TYPE;
        array_container_t *array = array_container_create_given_capacity(size);
        array_container_add_from_range(array, min, max, step);
        assert(array->cardinality == size);
        return array;
    } else {  // bitset container
        *type = BITSET_CONTAINER_TYPE;
        bitset_container_t *bitset = bitset_container_create();
        bitset_container_add_from_range(bitset, min, max, step);
        assert(bitset->cardinality == size);
        return bitset;
    }
}

/**
 * "repair" the container after lazy operations.
 */
static inline container_t *container_repair_after_lazy(
    container_t *c, uint8_t *type
){
    c = get_writable_copy_if_shared(c, type);  // !!! unnecessary cloning
    container_t *result = NULL;
    switch (*type) {
        case BITSET_CONTAINER_TYPE: {
            bitset_container_t *bc = CAST_bitset(c);
            bc->cardinality = bitset_container_compute_cardinality(bc);
            if (bc->cardinality <= DEFAULT_MAX_SIZE) {
                result = array_container_from_bitset(bc);
                bitset_container_free(bc);
                *type = ARRAY_CONTAINER_TYPE;
                return result;
            }
            return c; }
        case ARRAY_CONTAINER_TYPE:
            return c;  // nothing to do
        case RUN_CONTAINER_TYPE:
            return convert_run_to_efficient_container_and_free(
                            CAST_run(c), type);
        case SHARED_CONTAINER_TYPE:
            assert(false);
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

/**
 * Writes the underlying array to buf, outputs how many bytes were written.
 * This is meant to be byte-by-byte compatible with the Java and Go versions of
 * Roaring.
 * The number of bytes written should be
 * container_write(container, buf).
 *
 */
static inline int32_t container_write(
    const container_t *c, uint8_t typecode,
    char *buf
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_write(const_CAST_bitset(c), buf);
        case ARRAY_CONTAINER_TYPE:
            return array_container_write(const_CAST_array(c), buf);
        case RUN_CONTAINER_TYPE:
            return run_container_write(const_CAST_run(c), buf);
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

/**
 * Get the container size in bytes under portable serialization (see
 * container_write), requires a
 * typecode
 */
static inline int32_t container_size_in_bytes(
    const container_t *c, uint8_t typecode
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_size_in_bytes(const_CAST_bitset(c));
        case ARRAY_CONTAINER_TYPE:
            return array_container_size_in_bytes(const_CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_size_in_bytes(const_CAST_run(c));
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

/**
 * print the container (useful for debugging), requires a  typecode
 */
static void container_printf(const container_t *container, uint8_t typecode);

/**
 * print the content of the container as a comma-separated list of 32-bit values
 * starting at base, requires a  typecode
 */
static void container_printf_as_uint32_array(const container_t *container,
                                      uint8_t typecode, uint32_t base);

/**
 * Checks whether a container is not empty, requires a  typecode
 */
static inline bool container_nonzero_cardinality(
    const container_t *c, uint8_t typecode
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_const_nonzero_cardinality(
                            const_CAST_bitset(c));
        case ARRAY_CONTAINER_TYPE:
            return array_container_nonzero_cardinality(const_CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_nonzero_cardinality(const_CAST_run(c));
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

/**
 * Recover memory from a container, requires a  typecode
 */
static void container_free(container_t *container, uint8_t typecode);

/**
 * Convert a container to an array of values, requires a  typecode as well as a
 * "base" (most significant values)
 * Returns number of ints added.
 */
static inline int container_to_uint32_array(
    uint32_t *output,
    const container_t *c, uint8_t typecode,
    uint32_t base
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_to_uint32_array(
                            output, const_CAST_bitset(c), base);
        case ARRAY_CONTAINER_TYPE:
            return array_container_to_uint32_array(
                            output, const_CAST_array(c), base);
        case RUN_CONTAINER_TYPE:
            return run_container_to_uint32_array(
                            output, const_CAST_run(c), base);
    }
    assert(false);
    __builtin_unreachable();
    return 0;  // unreached
}

/**
 * Add a value to a container, requires a  typecode, fills in new_typecode and
 * return (possibly different) container.
 * This function may allocate a new container, and caller is responsible for
 * memory deallocation
 */
static inline container_t *container_add(
    container_t *c, uint16_t val,
    uint8_t typecode,  // !!! should be second argument?
    uint8_t *new_typecode
){
    c = get_writable_copy_if_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            bitset_container_set(CAST_bitset(c), val);
            *new_typecode = BITSET_CONTAINER_TYPE;
            return c;
        case ARRAY_CONTAINER_TYPE: {
            array_container_t *ac = CAST_array(c);
            if (array_container_try_add(ac, val, DEFAULT_MAX_SIZE) != -1) {
                *new_typecode = ARRAY_CONTAINER_TYPE;
                return ac;
            } else {
                bitset_container_t* bitset = bitset_container_from_array(ac);
                bitset_container_add(bitset, val);
                *new_typecode = BITSET_CONTAINER_TYPE;
                return bitset;
            }
        } break;
        case RUN_CONTAINER_TYPE:
            // per Java, no container type adjustments are done (revisit?)
            run_container_add(CAST_run(c), val);
            *new_typecode = RUN_CONTAINER_TYPE;
            return c;
        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Remove a value from a container, requires a  typecode, fills in new_typecode
 * and
 * return (possibly different) container.
 * This function may allocate a new container, and caller is responsible for
 * memory deallocation
 */
static inline container_t *container_remove(
    container_t *c, uint16_t val,
    uint8_t typecode,  // !!! should be second argument?
    uint8_t *new_typecode
){
    c = get_writable_copy_if_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            if (bitset_container_remove(CAST_bitset(c), val)) {
                int card = bitset_container_cardinality(CAST_bitset(c));
                if (card <= DEFAULT_MAX_SIZE) {
                    *new_typecode = ARRAY_CONTAINER_TYPE;
                    return array_container_from_bitset(CAST_bitset(c));
                }
            }
            *new_typecode = typecode;
            return c;
        case ARRAY_CONTAINER_TYPE:
            *new_typecode = typecode;
            array_container_remove(CAST_array(c), val);
            return c;
        case RUN_CONTAINER_TYPE:
            // per Java, no container type adjustments are done (revisit?)
            run_container_remove(CAST_run(c), val);
            *new_typecode = RUN_CONTAINER_TYPE;
            return c;
        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Check whether a value is in a container, requires a  typecode
 */
static inline bool container_contains(
    const container_t *c,
    uint16_t val,
    uint8_t typecode  // !!! should be second argument?
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_get(const_CAST_bitset(c), val);
        case ARRAY_CONTAINER_TYPE:
            return array_container_contains(const_CAST_array(c), val);
        case RUN_CONTAINER_TYPE:
            return run_container_contains(const_CAST_run(c), val);
        default:
            assert(false);
            __builtin_unreachable();
            return false;
    }
}

/**
 * Check whether a range of values from range_start (included) to range_end (excluded)
 * is in a container, requires a typecode
 */
static inline bool container_contains_range(
    const container_t *c,
    uint32_t range_start, uint32_t range_end,
    uint8_t typecode  // !!! should be second argument?
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_get_range(const_CAST_bitset(c),
                                                range_start, range_end);
        case ARRAY_CONTAINER_TYPE:
            return array_container_contains_range(const_CAST_array(c),
                                                    range_start, range_end);
        case RUN_CONTAINER_TYPE:
            return run_container_contains_range(const_CAST_run(c),
                                                    range_start, range_end);
        default:
            assert(false);
            __builtin_unreachable();
            return false;
    }
}

/**
 * Returns true if the two containers have the same content. Note that
 * two containers having different types can be "equal" in this sense.
 */
static inline bool container_equals(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            return bitset_container_equals(const_CAST_bitset(c1),
                                           const_CAST_bitset(c2));

        case CONTAINER_PAIR(BITSET,RUN):
            return run_container_equals_bitset(const_CAST_run(c2),
                                               const_CAST_bitset(c1));

        case CONTAINER_PAIR(RUN,BITSET):
            return run_container_equals_bitset(const_CAST_run(c1),
                                               const_CAST_bitset(c2));

        case CONTAINER_PAIR(BITSET,ARRAY):
            // java would always return false?
            return array_container_equal_bitset(const_CAST_array(c2),
                                                const_CAST_bitset(c1));

        case CONTAINER_PAIR(ARRAY,BITSET):
            // java would always return false?
            return array_container_equal_bitset(const_CAST_array(c1),
                                                const_CAST_bitset(c2));

        case CONTAINER_PAIR(ARRAY,RUN):
            return run_container_equals_array(const_CAST_run(c2),
                                              const_CAST_array(c1));

        case CONTAINER_PAIR(RUN,ARRAY):
            return run_container_equals_array(const_CAST_run(c1),
                                              const_CAST_array(c2));

        case CONTAINER_PAIR(ARRAY,ARRAY):
            return array_container_equals(const_CAST_array(c1),
                                          const_CAST_array(c2));

        case CONTAINER_PAIR(RUN,RUN):
            return run_container_equals(const_CAST_run(c1),
                                        const_CAST_run(c2));

        default:
            assert(false);
            __builtin_unreachable();
            return false;
    }
}

/**
 * Returns true if the container c1 is a subset of the container c2. Note that
 * c1 can be a subset of c2 even if they have a different type.
 */
static inline bool container_is_subset(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            return bitset_container_is_subset(const_CAST_bitset(c1),
                                              const_CAST_bitset(c2));

        case CONTAINER_PAIR(BITSET,RUN):
            return bitset_container_is_subset_run(const_CAST_bitset(c1),
                                                  const_CAST_run(c2));

        case CONTAINER_PAIR(RUN,BITSET):
            return run_container_is_subset_bitset(const_CAST_run(c1),
                                                  const_CAST_bitset(c2));

        case CONTAINER_PAIR(BITSET,ARRAY):
            return false;  // by construction, size(c1) > size(c2)

        case CONTAINER_PAIR(ARRAY,BITSET):
            return array_container_is_subset_bitset(const_CAST_array(c1),
                                                    const_CAST_bitset(c2));

        case CONTAINER_PAIR(ARRAY,RUN):
            return array_container_is_subset_run(const_CAST_array(c1),
                                                 const_CAST_run(c2));

        case CONTAINER_PAIR(RUN,ARRAY):
            return run_container_is_subset_array(const_CAST_run(c1),
                                                 const_CAST_array(c2));

        case CONTAINER_PAIR(ARRAY,ARRAY):
            return array_container_is_subset(const_CAST_array(c1),
                                             const_CAST_array(c2));

        case CONTAINER_PAIR(RUN,RUN):
            return run_container_is_subset(const_CAST_run(c1),
                                           const_CAST_run(c2));

        default:
            assert(false);
            __builtin_unreachable();
            return false;
    }
}

// macro-izations possibilities for generic non-inplace binary-op dispatch

/**
 * Compute intersection between two containers, generate a new container (having
 * type result_type), requires a typecode. This allocates new memory, caller
 * is responsible for deallocation.
 */
static inline container_t *container_and(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            *result_type = bitset_bitset_container_intersection(
                                const_CAST_bitset(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            result = array_container_create();
            array_container_intersection(const_CAST_array(c1),
                                         const_CAST_array(c2),
                                         CAST_array(result));
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            result = run_container_create();
            run_container_intersection(const_CAST_run(c1),
                                       const_CAST_run(c2),
                                       CAST_run(result));
            return convert_run_to_efficient_container_and_free(
                        CAST_run(result), result_type);

        case CONTAINER_PAIR(BITSET,ARRAY):
            result = array_container_create();
            array_bitset_container_intersection(const_CAST_array(c2),
                                                const_CAST_bitset(c1),
                                                CAST_array(result));
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            result = array_container_create();
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            array_bitset_container_intersection(const_CAST_array(c1),
                                                const_CAST_bitset(c2),
                                                CAST_array(result));
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            *result_type = run_bitset_container_intersection(
                                const_CAST_run(c2),
                                const_CAST_bitset(c1), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            *result_type = run_bitset_container_intersection(
                                const_CAST_run(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = array_container_create();
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            array_run_container_intersection(const_CAST_array(c1),
                                             const_CAST_run(c2),
                                             CAST_array(result));
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            result = array_container_create();
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            array_run_container_intersection(const_CAST_array(c2),
                                             const_CAST_run(c1),
                                             CAST_array(result));
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Compute the size of the intersection between two containers.
 */
static inline int container_and_cardinality(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            return bitset_container_and_justcard(
                const_CAST_bitset(c1), const_CAST_bitset(c2));

        case CONTAINER_PAIR(ARRAY,ARRAY):
            return array_container_intersection_cardinality(
                const_CAST_array(c1), const_CAST_array(c2));

        case CONTAINER_PAIR(RUN,RUN):
            return run_container_intersection_cardinality(
                const_CAST_run(c1), const_CAST_run(c2));

        case CONTAINER_PAIR(BITSET,ARRAY):
            return array_bitset_container_intersection_cardinality(
                const_CAST_array(c2), const_CAST_bitset(c1));

        case CONTAINER_PAIR(ARRAY,BITSET):
            return array_bitset_container_intersection_cardinality(
                const_CAST_array(c1), const_CAST_bitset(c2));

        case CONTAINER_PAIR(BITSET,RUN):
            return run_bitset_container_intersection_cardinality(
                const_CAST_run(c2), const_CAST_bitset(c1));

        case CONTAINER_PAIR(RUN,BITSET):
            return run_bitset_container_intersection_cardinality(
                const_CAST_run(c1), const_CAST_bitset(c2));

        case CONTAINER_PAIR(ARRAY,RUN):
            return array_run_container_intersection_cardinality(
                const_CAST_array(c1), const_CAST_run(c2));

        case CONTAINER_PAIR(RUN,ARRAY):
            return array_run_container_intersection_cardinality(
                const_CAST_array(c2), const_CAST_run(c1));

        default:
            assert(false);
            __builtin_unreachable();
            return 0;
    }
}

/**
 * Check whether two containers intersect.
 */
static inline bool container_intersect(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            return bitset_container_intersect(const_CAST_bitset(c1),
                                              const_CAST_bitset(c2));

        case CONTAINER_PAIR(ARRAY,ARRAY):
            return array_container_intersect(const_CAST_array(c1),
                                             const_CAST_array(c2));

        case CONTAINER_PAIR(RUN,RUN):
            return run_container_intersect(const_CAST_run(c1),
                                           const_CAST_run(c2));

        case CONTAINER_PAIR(BITSET,ARRAY):
            return array_bitset_container_intersect(const_CAST_array(c2),
                                                    const_CAST_bitset(c1));

        case CONTAINER_PAIR(ARRAY,BITSET):
            return array_bitset_container_intersect(const_CAST_array(c1),
                                                    const_CAST_bitset(c2));

        case CONTAINER_PAIR(BITSET,RUN):
            return run_bitset_container_intersect(const_CAST_run(c2),
                                                  const_CAST_bitset(c1));

        case CONTAINER_PAIR(RUN,BITSET):
            return run_bitset_container_intersect(const_CAST_run(c1),
                                                  const_CAST_bitset(c2));

        case CONTAINER_PAIR(ARRAY,RUN):
            return array_run_container_intersect(const_CAST_array(c1),
                                                 const_CAST_run(c2));

        case CONTAINER_PAIR(RUN,ARRAY):
            return array_run_container_intersect(const_CAST_array(c2),
                                                 const_CAST_run(c1));

        default:
            assert(false);
            __builtin_unreachable();
            return 0;
    }
}

/**
 * Compute intersection between two containers, with result in the first
 container if possible. If the returned pointer is identical to c1,
 then the container has been modified. If the returned pointer is different
 from c1, then a new container has been created and the caller is responsible
 for freeing it.
 The type of the first container may change. Returns the modified
 (and possibly new) container.
*/
static inline container_t *container_iand(
    container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = get_writable_copy_if_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            *result_type =
                bitset_bitset_container_intersection_inplace(
                    CAST_bitset(c1), const_CAST_bitset(c2), &result)
                        ? BITSET_CONTAINER_TYPE
                        : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            array_container_intersection_inplace(CAST_array(c1),
                                                 const_CAST_array(c2));
            *result_type = ARRAY_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(RUN,RUN):
            result = run_container_create();
            run_container_intersection(const_CAST_run(c1),
                                       const_CAST_run(c2),
                                       CAST_run(result));
            // as of January 2016, Java code used non-in-place intersection for
            // two runcontainers
            return convert_run_to_efficient_container_and_free(
                            CAST_run(result), result_type);

        case CONTAINER_PAIR(BITSET,ARRAY):
            // c1 is a bitmap so no inplace possible
            result = array_container_create();
            array_bitset_container_intersection(const_CAST_array(c2),
                                                const_CAST_bitset(c1),
                                                CAST_array(result));
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            array_bitset_container_intersection(
                    const_CAST_array(c1), const_CAST_bitset(c2),
                    CAST_array(c1));  // result is allowed to be same as c1
            return c1;

        case CONTAINER_PAIR(BITSET,RUN):
            // will attempt in-place computation
            *result_type = run_bitset_container_intersection(
                                const_CAST_run(c2),
                                const_CAST_bitset(c1), &c1)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(RUN,BITSET):
            *result_type = run_bitset_container_intersection(
                                const_CAST_run(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = array_container_create();
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            array_run_container_intersection(const_CAST_array(c1),
                                             const_CAST_run(c2),
                                             CAST_array(result));
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            result = array_container_create();
            *result_type = ARRAY_CONTAINER_TYPE;  // never bitset
            array_run_container_intersection(const_CAST_array(c2),
                                             const_CAST_run(c1),
                                             CAST_array(result));
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Compute union between two containers, generate a new container (having type
 * result_type), requires a typecode. This allocates new memory, caller
 * is responsible for deallocation.
 */
static inline container_t *container_or(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            result = bitset_container_create();
            bitset_container_or(const_CAST_bitset(c1),
                                const_CAST_bitset(c2),
                                CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_union(
                                const_CAST_array(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            result = run_container_create();
            run_container_union(const_CAST_run(c1),
                                const_CAST_run(c2),
                                CAST_run(result));
            *result_type = RUN_CONTAINER_TYPE;
            // todo: could be optimized since will never convert to array
            result = convert_run_to_efficient_container_and_free(
                            CAST_run(result), result_type);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            result = bitset_container_create();
            array_bitset_container_union(const_CAST_array(c2),
                                         const_CAST_bitset(c1),
                                         CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            result = bitset_container_create();
            array_bitset_container_union(const_CAST_array(c1),
                                         const_CAST_bitset(c2),
                                         CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = run_container_create();
                *result_type = RUN_CONTAINER_TYPE;
                run_container_copy(const_CAST_run(c2),
                                   CAST_run(result));
                return result;
            }
            result = bitset_container_create();
            run_bitset_container_union(const_CAST_run(c2),
                                       const_CAST_bitset(c1),
                                       CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            if (run_container_is_full(const_CAST_run(c1))) {
                result = run_container_create();
                *result_type = RUN_CONTAINER_TYPE;
                run_container_copy(const_CAST_run(c1),
                                   CAST_run(result));
                return result;
            }
            result = bitset_container_create();
            run_bitset_container_union(const_CAST_run(c1),
                                       const_CAST_bitset(c2),
                                       CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = run_container_create();
            array_run_container_union(const_CAST_array(c1),
                                      const_CAST_run(c2),
                                      CAST_run(result));
            result = convert_run_to_efficient_container_and_free(
                            CAST_run(result), result_type);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            result = run_container_create();
            array_run_container_union(const_CAST_array(c2),
                                      const_CAST_run(c1),
                                      CAST_run(result));
            result = convert_run_to_efficient_container_and_free(
                            CAST_run(result), result_type);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;  // unreached
    }
}

/**
 * Compute union between two containers, generate a new container (having type
 * result_type), requires a typecode. This allocates new memory, caller
 * is responsible for deallocation.
 *
 * This lazy version delays some operations such as the maintenance of the
 * cardinality. It requires repair later on the generated containers.
 */
static inline container_t *container_lazy_or(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            result = bitset_container_create();
            bitset_container_or_nocard(
                    const_CAST_bitset(c1), const_CAST_bitset(c2),
                    CAST_bitset(result));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_lazy_union(
                                const_CAST_array(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            result = run_container_create();
            run_container_union(const_CAST_run(c1),
                                const_CAST_run(c2),
                                CAST_run(result));
            *result_type = RUN_CONTAINER_TYPE;
            // we are being lazy
            result = convert_run_to_efficient_container(
                CAST_run(result), result_type);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            result = bitset_container_create();
            array_bitset_container_lazy_union(
                    const_CAST_array(c2), const_CAST_bitset(c1),
                    CAST_bitset(result));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            result = bitset_container_create();
            array_bitset_container_lazy_union(
                    const_CAST_array(c1), const_CAST_bitset(c2),
                    CAST_bitset(result));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = run_container_create();
                *result_type = RUN_CONTAINER_TYPE;
                run_container_copy(const_CAST_run(c2), CAST_run(result));
                return result;
            }
            result = bitset_container_create();
            run_bitset_container_lazy_union(
                const_CAST_run(c2), const_CAST_bitset(c1),
                CAST_bitset(result));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            if (run_container_is_full(const_CAST_run(c1))) {
                result = run_container_create();
                *result_type = RUN_CONTAINER_TYPE;
                run_container_copy(const_CAST_run(c1), CAST_run(result));
                return result;
            }
            result = bitset_container_create();
            run_bitset_container_lazy_union(
                const_CAST_run(c1), const_CAST_bitset(c2),
                CAST_bitset(result));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = run_container_create();
            array_run_container_union(const_CAST_array(c1),
                                      const_CAST_run(c2),
                                      CAST_run(result));
            *result_type = RUN_CONTAINER_TYPE;
            // next line skipped since we are lazy
            // result = convert_run_to_efficient_container(result, result_type);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            result = run_container_create();
            array_run_container_union(
                const_CAST_array(c2), const_CAST_run(c1),
                CAST_run(result));  // TODO make lazy
            *result_type = RUN_CONTAINER_TYPE;
            // next line skipped since we are lazy
            // result = convert_run_to_efficient_container(result, result_type);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;  // unreached
    }
}

/**
 * Compute the union between two containers, with result in the first container.
 * If the returned pointer is identical to c1, then the container has been
 * modified.
 * If the returned pointer is different from c1, then a new container has been
 * created and the caller is responsible for freeing it.
 * The type of the first container may change. Returns the modified
 * (and possibly new) container
*/
static inline container_t *container_ior(
    container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = get_writable_copy_if_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            bitset_container_or(const_CAST_bitset(c1),
                                const_CAST_bitset(c2),
                                CAST_bitset(c1));
#ifdef OR_BITSET_CONVERSION_TO_FULL
            if (CAST_bitset(c1)->cardinality == (1 << 16)) {  // we convert
                result = run_container_create_range(0, (1 << 16));
                *result_type = RUN_CONTAINER_TYPE;
                return result;
            }
#endif
            *result_type = BITSET_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_inplace_union(
                                CAST_array(c1), const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            if((result == NULL)
               && (*result_type == ARRAY_CONTAINER_TYPE)) {
                 return c1; // the computation was done in-place!
            }
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            run_container_union_inplace(CAST_run(c1), const_CAST_run(c2));
            return convert_run_to_efficient_container(CAST_run(c1),
                                                      result_type);

        case CONTAINER_PAIR(BITSET,ARRAY):
            array_bitset_container_union(const_CAST_array(c2),
                                         const_CAST_bitset(c1),
                                         CAST_bitset(c1));
            *result_type = BITSET_CONTAINER_TYPE;  // never array
            return c1;

        case CONTAINER_PAIR(ARRAY,BITSET):
            // c1 is an array, so no in-place possible
            result = bitset_container_create();
            *result_type = BITSET_CONTAINER_TYPE;
            array_bitset_container_union(const_CAST_array(c1),
                                         const_CAST_bitset(c2),
                                         CAST_bitset(result));
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = run_container_create();
                *result_type = RUN_CONTAINER_TYPE;
                run_container_copy(const_CAST_run(c2), CAST_run(result));
                return result;
            }
            run_bitset_container_union(const_CAST_run(c2),
                                       const_CAST_bitset(c1),
                                       CAST_bitset(c1));  // allowed
            *result_type = BITSET_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(RUN,BITSET):
            if (run_container_is_full(const_CAST_run(c1))) {
                *result_type = RUN_CONTAINER_TYPE;
                return c1;
            }
            result = bitset_container_create();
            run_bitset_container_union(const_CAST_run(c1),
                                       const_CAST_bitset(c2),
                                       CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = run_container_create();
            array_run_container_union(const_CAST_array(c1),
                                      const_CAST_run(c2),
                                      CAST_run(result));
            result = convert_run_to_efficient_container_and_free(
                            CAST_run(result), result_type);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            array_run_container_inplace_union(const_CAST_array(c2),
                                              CAST_run(c1));
            c1 = convert_run_to_efficient_container(CAST_run(c1),
                                                    result_type);
            return c1;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Compute the union between two containers, with result in the first container.
 * If the returned pointer is identical to c1, then the container has been
 * modified.
 * If the returned pointer is different from c1, then a new container has been
 * created and the caller is responsible for freeing it.
 * The type of the first container may change. Returns the modified
 * (and possibly new) container
 *
 * This lazy version delays some operations such as the maintenance of the
 * cardinality. It requires repair later on the generated containers.
*/
static inline container_t *container_lazy_ior(
    container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    assert(type1 != SHARED_CONTAINER_TYPE);
    // c1 = get_writable_copy_if_shared(c1,&type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
#ifdef LAZY_OR_BITSET_CONVERSION_TO_FULL
            // if we have two bitsets, we might as well compute the cardinality
            bitset_container_or(const_CAST_bitset(c1),
                                const_CAST_bitset(c2),
                                CAST_bitset(c1));
            // it is possible that two bitsets can lead to a full container
            if (CAST_bitset(c1)->cardinality == (1 << 16)) {  // we convert
                result = run_container_create_range(0, (1 << 16));
                *result_type = RUN_CONTAINER_TYPE;
                return result;
            }
#else
            bitset_container_or_nocard(const_CAST_bitset(c1),
                                       const_CAST_bitset(c2),
                                       CAST_bitset(c1));

#endif
            *result_type = BITSET_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_lazy_inplace_union(
                                CAST_array(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            if((result == NULL)
               && (*result_type == ARRAY_CONTAINER_TYPE)) {
                 return c1; // the computation was done in-place!
            }
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            run_container_union_inplace(CAST_run(c1),
                                        const_CAST_run(c2));
            *result_type = RUN_CONTAINER_TYPE;
            return convert_run_to_efficient_container(CAST_run(c1),
                                                      result_type);

        case CONTAINER_PAIR(BITSET,ARRAY):
            array_bitset_container_lazy_union(
                    const_CAST_array(c2), const_CAST_bitset(c1),
                    CAST_bitset(c1));              // is lazy
            *result_type = BITSET_CONTAINER_TYPE;  // never array
            return c1;

        case CONTAINER_PAIR(ARRAY,BITSET):
            // c1 is an array, so no in-place possible
            result = bitset_container_create();
            *result_type = BITSET_CONTAINER_TYPE;
            array_bitset_container_lazy_union(
                    const_CAST_array(c1), const_CAST_bitset(c2),
                    CAST_bitset(result));  // is lazy
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = run_container_create();
                *result_type = RUN_CONTAINER_TYPE;
                run_container_copy(const_CAST_run(c2),
                                   CAST_run(result));
                return result;
            }
            run_bitset_container_lazy_union(
                const_CAST_run(c2), const_CAST_bitset(c1),
                CAST_bitset(c1));  // allowed //  lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(RUN,BITSET):
            if (run_container_is_full(const_CAST_run(c1))) {
                *result_type = RUN_CONTAINER_TYPE;
                return c1;
            }
            result = bitset_container_create();
            run_bitset_container_lazy_union(
                const_CAST_run(c1), const_CAST_bitset(c2),
                CAST_bitset(result));  //  lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = run_container_create();
            array_run_container_union(const_CAST_array(c1),
                                      const_CAST_run(c2),
                                      CAST_run(result));
            *result_type = RUN_CONTAINER_TYPE;
            // next line skipped since we are lazy
            // result = convert_run_to_efficient_container_and_free(result,
            // result_type);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            array_run_container_inplace_union(const_CAST_array(c2),
                                              CAST_run(c1));
            *result_type = RUN_CONTAINER_TYPE;
            // next line skipped since we are lazy
            // result = convert_run_to_efficient_container_and_free(result,
            // result_type);
            return c1;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Compute symmetric difference (xor) between two containers, generate a new
 * container (having type result_type), requires a typecode. This allocates new
 * memory, caller is responsible for deallocation.
 */
static inline container_t* container_xor(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            *result_type = bitset_bitset_container_xor(
                                const_CAST_bitset(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_xor(
                                const_CAST_array(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            *result_type =
                run_run_container_xor(const_CAST_run(c1),
                                      const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            *result_type = array_bitset_container_xor(
                                const_CAST_array(c2),
                                const_CAST_bitset(c1), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            *result_type = array_bitset_container_xor(
                                const_CAST_array(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            *result_type = run_bitset_container_xor(
                                const_CAST_run(c2),
                                const_CAST_bitset(c1), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            *result_type = run_bitset_container_xor(
                                const_CAST_run(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            *result_type =
                array_run_container_xor(const_CAST_array(c1),
                                        const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            *result_type =
                array_run_container_xor(const_CAST_array(c2),
                                        const_CAST_run(c1), &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;  // unreached
    }
}

/**
 * Compute xor between two containers, generate a new container (having type
 * result_type), requires a typecode. This allocates new memory, caller
 * is responsible for deallocation.
 *
 * This lazy version delays some operations such as the maintenance of the
 * cardinality. It requires repair later on the generated containers.
 */
static inline container_t *container_lazy_xor(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            result = bitset_container_create();
            bitset_container_xor_nocard(
                const_CAST_bitset(c1), const_CAST_bitset(c2),
                CAST_bitset(result));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_lazy_xor(
                                const_CAST_array(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            // nothing special done yet.
            *result_type =
                run_run_container_xor(const_CAST_run(c1),
                                      const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            result = bitset_container_create();
            *result_type = BITSET_CONTAINER_TYPE;
            array_bitset_container_lazy_xor(const_CAST_array(c2),
                                            const_CAST_bitset(c1),
                                            CAST_bitset(result));
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            result = bitset_container_create();
            *result_type = BITSET_CONTAINER_TYPE;
            array_bitset_container_lazy_xor(const_CAST_array(c1),
                                            const_CAST_bitset(c2),
                                            CAST_bitset(result));
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            result = bitset_container_create();
            run_bitset_container_lazy_xor(const_CAST_run(c2),
                                          const_CAST_bitset(c1),
                                          CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            result = bitset_container_create();
            run_bitset_container_lazy_xor(const_CAST_run(c1),
                                          const_CAST_bitset(c2),
                                          CAST_bitset(result));
            *result_type = BITSET_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            result = run_container_create();
            array_run_container_lazy_xor(const_CAST_array(c1),
                                         const_CAST_run(c2),
                                         CAST_run(result));
            *result_type = RUN_CONTAINER_TYPE;
            // next line skipped since we are lazy
            // result = convert_run_to_efficient_container(result, result_type);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            result = run_container_create();
            array_run_container_lazy_xor(const_CAST_array(c2),
                                         const_CAST_run(c1),
                                         CAST_run(result));
            *result_type = RUN_CONTAINER_TYPE;
            // next line skipped since we are lazy
            // result = convert_run_to_efficient_container(result, result_type);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;  // unreached
    }
}

/**
 * Compute the xor between two containers, with result in the first container.
 * If the returned pointer is identical to c1, then the container has been
 * modified.
 * If the returned pointer is different from c1, then a new container has been
 * created and the caller is responsible for freeing it.
 * The type of the first container may change. Returns the modified
 * (and possibly new) container
*/
static inline container_t *container_ixor(
    container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = get_writable_copy_if_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            *result_type = bitset_bitset_container_ixor(
                                CAST_bitset(c1), const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            *result_type = array_array_container_ixor(
                                CAST_array(c1), const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            *result_type = run_run_container_ixor(
                CAST_run(c1), const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            *result_type = bitset_array_container_ixor(
                                CAST_bitset(c1), const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            *result_type = array_bitset_container_ixor(
                                CAST_array(c1), const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            *result_type =
                bitset_run_container_ixor(
                    CAST_bitset(c1), const_CAST_run(c2), &result)
                        ? BITSET_CONTAINER_TYPE
                        : ARRAY_CONTAINER_TYPE;

            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            *result_type = run_bitset_container_ixor(
                                CAST_run(c1), const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            *result_type = array_run_container_ixor(
                                CAST_array(c1), const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            *result_type = run_array_container_ixor(
                                CAST_run(c1), const_CAST_array(c2), &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Compute the xor between two containers, with result in the first container.
 * If the returned pointer is identical to c1, then the container has been
 * modified.
 * If the returned pointer is different from c1, then a new container has been
 * created and the caller is responsible for freeing it.
 * The type of the first container may change. Returns the modified
 * (and possibly new) container
 *
 * This lazy version delays some operations such as the maintenance of the
 * cardinality. It requires repair later on the generated containers.
*/
static inline container_t *container_lazy_ixor(
    container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    assert(type1 != SHARED_CONTAINER_TYPE);
    // c1 = get_writable_copy_if_shared(c1,&type1);
    c2 = container_unwrap_shared(c2, &type2);
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            bitset_container_xor_nocard(CAST_bitset(c1),
                                        const_CAST_bitset(c2),
                                        CAST_bitset(c1));  // is lazy
            *result_type = BITSET_CONTAINER_TYPE;
            return c1;

        // TODO: other cases being lazy, esp. when we know inplace not likely
        // could see the corresponding code for union
        default:
            // we may have a dirty bitset (without a precomputed cardinality)
            // and calling container_ixor on it might be unsafe.
            if (type1 == BITSET_CONTAINER_TYPE) {
                bitset_container_t *bc = CAST_bitset(c1);
                if (bc->cardinality == BITSET_UNKNOWN_CARDINALITY) {
                    bc->cardinality = bitset_container_compute_cardinality(bc);
                }
            }
            return container_ixor(c1, type1, c2, type2, result_type);
    }
}

/**
 * Compute difference (andnot) between two containers, generate a new
 * container (having type result_type), requires a typecode. This allocates new
 * memory, caller is responsible for deallocation.
 */
static inline container_t *container_andnot(
    const container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = container_unwrap_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            *result_type = bitset_bitset_container_andnot(
                                const_CAST_bitset(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            result = array_container_create();
            array_array_container_andnot(const_CAST_array(c1),
                                         const_CAST_array(c2),
                                         CAST_array(result));
            *result_type = ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = array_container_create();
                *result_type = ARRAY_CONTAINER_TYPE;
                return result;
            }
            *result_type =
                run_run_container_andnot(const_CAST_run(c1),
                                         const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            *result_type = bitset_array_container_andnot(
                                const_CAST_bitset(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            result = array_container_create();
            array_bitset_container_andnot(const_CAST_array(c1),
                                          const_CAST_bitset(c2),
                                          CAST_array(result));
            *result_type = ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(BITSET,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = array_container_create();
                *result_type = ARRAY_CONTAINER_TYPE;
                return result;
            }
            *result_type = bitset_run_container_andnot(
                                const_CAST_bitset(c1),
                                const_CAST_run(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            *result_type = run_bitset_container_andnot(
                                const_CAST_run(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            if (run_container_is_full(const_CAST_run(c2))) {
                result = array_container_create();
                *result_type = ARRAY_CONTAINER_TYPE;
                return result;
            }
            result = array_container_create();
            array_run_container_andnot(const_CAST_array(c1),
                                       const_CAST_run(c2),
                                       CAST_array(result));
            *result_type = ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,ARRAY):
            *result_type = run_array_container_andnot(
                const_CAST_run(c1), const_CAST_array(c2),
                &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;  // unreached
    }
}

/**
 * Compute the andnot between two containers, with result in the first
 * container.
 * If the returned pointer is identical to c1, then the container has been
 * modified.
 * If the returned pointer is different from c1, then a new container has been
 * created and the caller is responsible for freeing it.
 * The type of the first container may change. Returns the modified
 * (and possibly new) container
*/
static inline container_t *container_iandnot(
    container_t *c1, uint8_t type1,
    const container_t *c2, uint8_t type2,
    uint8_t *result_type
){
    c1 = get_writable_copy_if_shared(c1, &type1);
    c2 = container_unwrap_shared(c2, &type2);
    container_t *result = NULL;
    switch (PAIR_CONTAINER_TYPES(type1, type2)) {
        case CONTAINER_PAIR(BITSET,BITSET):
            *result_type = bitset_bitset_container_iandnot(
                                CAST_bitset(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,ARRAY):
            array_array_container_iandnot(CAST_array(c1),
                                          const_CAST_array(c2));
            *result_type = ARRAY_CONTAINER_TYPE;
            return c1;

        case CONTAINER_PAIR(RUN,RUN):
            *result_type = run_run_container_iandnot(
                CAST_run(c1), const_CAST_run(c2), &result);
            return result;

        case CONTAINER_PAIR(BITSET,ARRAY):
            *result_type = bitset_array_container_iandnot(
                                CAST_bitset(c1),
                                const_CAST_array(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,BITSET):
            *result_type = ARRAY_CONTAINER_TYPE;
            array_bitset_container_iandnot(CAST_array(c1),
                                           const_CAST_bitset(c2));
            return c1;

        case CONTAINER_PAIR(BITSET,RUN):
            *result_type = bitset_run_container_iandnot(
                                CAST_bitset(c1),
                                const_CAST_run(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(RUN,BITSET):
            *result_type = run_bitset_container_iandnot(
                                CAST_run(c1),
                                const_CAST_bitset(c2), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;

        case CONTAINER_PAIR(ARRAY,RUN):
            *result_type = ARRAY_CONTAINER_TYPE;
            array_run_container_iandnot(CAST_array(c1),
                                        const_CAST_run(c2));
            return c1;

        case CONTAINER_PAIR(RUN,ARRAY):
            *result_type = run_array_container_iandnot(
                CAST_run(c1), const_CAST_array(c2), &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

/**
 * Visit all values x of the container once, passing (base+x,ptr)
 * to iterator. You need to specify a container and its type.
 * Returns true if the iteration should continue.
 */
static inline bool container_iterate(
    const container_t *c, uint8_t type,
    uint32_t base,
    roaring_iterator iterator, void *ptr
){
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_iterate(const_CAST_bitset(c),
                                            base, iterator, ptr);
        case ARRAY_CONTAINER_TYPE:
            return array_container_iterate(const_CAST_array(c),
                                           base, iterator, ptr);
        case RUN_CONTAINER_TYPE:
            return run_container_iterate(const_CAST_run(c),
                                         base, iterator, ptr);
        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return false;
}

static inline bool container_iterate64(
    const container_t *c, uint8_t type,
    uint32_t base,
    roaring_iterator64 iterator,
    uint64_t high_bits, void *ptr
){
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_iterate64(const_CAST_bitset(c), base,
                                              iterator, high_bits, ptr);
        case ARRAY_CONTAINER_TYPE:
            return array_container_iterate64(const_CAST_array(c), base,
                                             iterator, high_bits, ptr);
        case RUN_CONTAINER_TYPE:
            return run_container_iterate64(const_CAST_run(c), base,
                                           iterator, high_bits, ptr);
        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return false;
}

static inline container_t *container_not(
    const container_t *c, uint8_t type,
    uint8_t *result_type
){
    c = container_unwrap_shared(c, &type);
    container_t *result = NULL;
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            *result_type = bitset_container_negation(
                                const_CAST_bitset(c), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;
        case ARRAY_CONTAINER_TYPE:
            result = bitset_container_create();
            *result_type = BITSET_CONTAINER_TYPE;
            array_container_negation(const_CAST_array(c),
                                     CAST_bitset(result));
            return result;
        case RUN_CONTAINER_TYPE:
            *result_type =
                run_container_negation(const_CAST_run(c), &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return NULL;
}

static inline container_t *container_not_range(
    const container_t *c, uint8_t type,
    uint32_t range_start, uint32_t range_end,
    uint8_t *result_type
){
    c = container_unwrap_shared(c, &type);
    container_t *result = NULL;
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            *result_type =
                bitset_container_negation_range(
                        const_CAST_bitset(c), range_start, range_end, &result)
                            ? BITSET_CONTAINER_TYPE
                            : ARRAY_CONTAINER_TYPE;
            return result;
        case ARRAY_CONTAINER_TYPE:
            *result_type =
                array_container_negation_range(
                    const_CAST_array(c), range_start, range_end, &result)
                        ? BITSET_CONTAINER_TYPE
                        : ARRAY_CONTAINER_TYPE;
            return result;
        case RUN_CONTAINER_TYPE:
            *result_type = run_container_negation_range(
                            const_CAST_run(c), range_start, range_end, &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return NULL;
}

static inline container_t *container_inot(
    container_t *c, uint8_t type,
    uint8_t *result_type
){
    c = get_writable_copy_if_shared(c, &type);
    container_t *result = NULL;
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            *result_type = bitset_container_negation_inplace(
                                CAST_bitset(c), &result)
                                    ? BITSET_CONTAINER_TYPE
                                    : ARRAY_CONTAINER_TYPE;
            return result;
        case ARRAY_CONTAINER_TYPE:
            // will never be inplace
            result = bitset_container_create();
            *result_type = BITSET_CONTAINER_TYPE;
            array_container_negation(CAST_array(c),
                                     CAST_bitset(result));
            array_container_free(CAST_array(c));
            return result;
        case RUN_CONTAINER_TYPE:
            *result_type =
                run_container_negation_inplace(CAST_run(c), &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return NULL;
}

static inline container_t *container_inot_range(
    container_t *c, uint8_t type,
    uint32_t range_start, uint32_t range_end,
    uint8_t *result_type
){
    c = get_writable_copy_if_shared(c, &type);
    container_t *result = NULL;
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            *result_type =
                bitset_container_negation_range_inplace(
                    CAST_bitset(c), range_start, range_end, &result)
                        ? BITSET_CONTAINER_TYPE
                        : ARRAY_CONTAINER_TYPE;
            return result;
        case ARRAY_CONTAINER_TYPE:
            *result_type =
                array_container_negation_range_inplace(
                    CAST_array(c), range_start, range_end, &result)
                        ? BITSET_CONTAINER_TYPE
                        : ARRAY_CONTAINER_TYPE;
            return result;
        case RUN_CONTAINER_TYPE:
            *result_type = run_container_negation_range_inplace(
                                CAST_run(c), range_start, range_end, &result);
            return result;

        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return NULL;
}

/**
 * If the element of given rank is in this container, supposing that
 * the first
 * element has rank start_rank, then the function returns true and
 * sets element
 * accordingly.
 * Otherwise, it returns false and update start_rank.
 */
static inline bool container_select(
    const container_t *c, uint8_t type,
    uint32_t *start_rank, uint32_t rank,
    uint32_t *element
){
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_select(const_CAST_bitset(c),
                                           start_rank, rank, element);
        case ARRAY_CONTAINER_TYPE:
            return array_container_select(const_CAST_array(c),
                                          start_rank, rank, element);
        case RUN_CONTAINER_TYPE:
            return run_container_select(const_CAST_run(c),
                                        start_rank, rank, element);
        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return false;
}

static inline uint16_t container_maximum(
    const container_t *c, uint8_t type
){
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_maximum(const_CAST_bitset(c));
        case ARRAY_CONTAINER_TYPE:
            return array_container_maximum(const_CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_maximum(const_CAST_run(c));
        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return false;
}

static inline uint16_t container_minimum(
    const container_t *c, uint8_t type
){
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_minimum(const_CAST_bitset(c));
        case ARRAY_CONTAINER_TYPE:
            return array_container_minimum(const_CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_minimum(const_CAST_run(c));
        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return false;
}

// number of values smaller or equal to x
static inline int container_rank(
    const container_t *c, uint8_t type,
    uint16_t x
){
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_rank(const_CAST_bitset(c), x);
        case ARRAY_CONTAINER_TYPE:
            return array_container_rank(const_CAST_array(c), x);
        case RUN_CONTAINER_TYPE:
            return run_container_rank(const_CAST_run(c), x);
        default:
            assert(false);
            __builtin_unreachable();
    }
    assert(false);
    __builtin_unreachable();
    return false;
}

/**
 * Add all values in range [min, max] to a given container.
 *
 * If the returned pointer is different from $container, then a new container
 * has been created and the caller is responsible for freeing it.
 * The type of the first container may change. Returns the modified
 * (and possibly new) container.
 */
static inline container_t *container_add_range(
    container_t *c, uint8_t type,
    uint32_t min, uint32_t max,
    uint8_t *result_type
){
    // NB: when selecting new container type, we perform only inexpensive checks
    switch (type) {
        case BITSET_CONTAINER_TYPE: {
            bitset_container_t *bitset = CAST_bitset(c);

            int32_t union_cardinality = 0;
            union_cardinality += bitset->cardinality;
            union_cardinality += max - min + 1;
            union_cardinality -= bitset_lenrange_cardinality(bitset->words,
                                                             min, max-min);

            if (union_cardinality == INT32_C(0x10000)) {
                *result_type = RUN_CONTAINER_TYPE;
                return run_container_create_range(0, INT32_C(0x10000));
            } else {
                *result_type = BITSET_CONTAINER_TYPE;
                bitset_set_lenrange(bitset->words, min, max - min);
                bitset->cardinality = union_cardinality;
                return bitset;
            }
        }
        case ARRAY_CONTAINER_TYPE: {
            array_container_t *array = CAST_array(c);

            int32_t nvals_greater = count_greater(array->array, array->cardinality, max);
            int32_t nvals_less = count_less(array->array, array->cardinality - nvals_greater, min);
            int32_t union_cardinality = nvals_less + (max - min + 1) + nvals_greater;

            if (union_cardinality == INT32_C(0x10000)) {
                *result_type = RUN_CONTAINER_TYPE;
                return run_container_create_range(0, INT32_C(0x10000));
            } else if (union_cardinality <= DEFAULT_MAX_SIZE) {
                *result_type = ARRAY_CONTAINER_TYPE;
                array_container_add_range_nvals(array, min, max, nvals_less, nvals_greater);
                return array;
            } else {
                *result_type = BITSET_CONTAINER_TYPE;
                bitset_container_t *bitset = bitset_container_from_array(array);
                bitset_set_lenrange(bitset->words, min, max - min);
                bitset->cardinality = union_cardinality;
                return bitset;
            }
        }
        case RUN_CONTAINER_TYPE: {
            run_container_t *run = CAST_run(c);

            int32_t nruns_greater = rle16_count_greater(run->runs, run->n_runs, max);
            int32_t nruns_less = rle16_count_less(run->runs, run->n_runs - nruns_greater, min);

            int32_t run_size_bytes = (nruns_less + 1 + nruns_greater) * sizeof(rle16_t);
            int32_t bitset_size_bytes = BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);

            if (run_size_bytes <= bitset_size_bytes) {
                run_container_add_range_nruns(run, min, max, nruns_less, nruns_greater);
                *result_type = RUN_CONTAINER_TYPE;
                return run;
            } else {
                return container_from_run_range(run, min, max, result_type);
            }
        }
        default:
            __builtin_unreachable();
    }
}

/*
 * Removes all elements in range [min, max].
 * Returns one of:
 *   - NULL if no elements left
 *   - pointer to the original container
 *   - pointer to a newly-allocated container (if it is more efficient)
 *
 * If the returned pointer is different from $container, then a new container
 * has been created and the caller is responsible for freeing the original container.
 */
static inline container_t *container_remove_range(
    container_t *c, uint8_t type,
    uint32_t min, uint32_t max,
    uint8_t *result_type
){
     switch (type) {
        case BITSET_CONTAINER_TYPE: {
            bitset_container_t *bitset = CAST_bitset(c);

            int32_t result_cardinality = bitset->cardinality -
                bitset_lenrange_cardinality(bitset->words, min, max-min);

            if (result_cardinality == 0) {
                return NULL;
            } else if (result_cardinality < DEFAULT_MAX_SIZE) {
                *result_type = ARRAY_CONTAINER_TYPE;
                bitset_reset_range(bitset->words, min, max+1);
                bitset->cardinality = result_cardinality;
                return array_container_from_bitset(bitset);
            } else {
                *result_type = BITSET_CONTAINER_TYPE;
                bitset_reset_range(bitset->words, min, max+1);
                bitset->cardinality = result_cardinality;
                return bitset;
            }
        }
        case ARRAY_CONTAINER_TYPE: {
            array_container_t *array = CAST_array(c);

            int32_t nvals_greater = count_greater(array->array, array->cardinality, max);
            int32_t nvals_less = count_less(array->array, array->cardinality - nvals_greater, min);
            int32_t result_cardinality = nvals_less + nvals_greater;

            if (result_cardinality == 0) {
                return NULL;
            } else {
                *result_type = ARRAY_CONTAINER_TYPE;
                array_container_remove_range(array, nvals_less,
                    array->cardinality - result_cardinality);
                return array;
            }
        }
        case RUN_CONTAINER_TYPE: {
            run_container_t *run = CAST_run(c);

            if (run->n_runs == 0) {
                return NULL;
            }
            if (min <= run_container_minimum(run) && max >= run_container_maximum(run)) {
                return NULL;
            }

            run_container_remove_range(run, min, max);

            if (run_container_serialized_size_in_bytes(run->n_runs) <=
                    bitset_container_serialized_size_in_bytes()) {
                *result_type = RUN_CONTAINER_TYPE;
                return run;
            } else {
                *result_type = BITSET_CONTAINER_TYPE;
                return bitset_container_from_run(run);
            }
        }
        default:
            __builtin_unreachable();
     }
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif

#endif
/* end file include/roaring/containers/containers.h */
/* begin file include/roaring/roaring_array.h */
#ifndef INCLUDE_ROARING_ARRAY_H
#define INCLUDE_ROARING_ARRAY_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" { namespace roaring {

// Note: in pure C++ code, you should avoid putting `using` in header files
using api::roaring_array_t;

namespace internal {
#endif

enum {
    SERIAL_COOKIE_NO_RUNCONTAINER = 12346,
    SERIAL_COOKIE = 12347,
    FROZEN_COOKIE = 13766,
    NO_OFFSET_THRESHOLD = 4
};

/**
 * Create a new roaring array
 */
static roaring_array_t *ra_create(void);

/**
 * Initialize an existing roaring array with the specified capacity (in number
 * of containers)
 */
static bool ra_init_with_capacity(roaring_array_t *new_ra, uint32_t cap);

/**
 * Initialize with zero capacity
 */
static void ra_init(roaring_array_t *t);

/**
 * Copies this roaring array, we assume that dest is not initialized
 */
static bool ra_copy(const roaring_array_t *source, roaring_array_t *dest,
             bool copy_on_write);

/*
 * Shrinks the capacity, returns the number of bytes saved.
 */
static int ra_shrink_to_fit(roaring_array_t *ra);

/**
 * Copies this roaring array, we assume that dest is initialized
 */
static bool ra_overwrite(const roaring_array_t *source, roaring_array_t *dest,
                  bool copy_on_write);

/**
 * Frees the memory used by a roaring array
 */
static void ra_clear(roaring_array_t *r);

/**
 * Frees the memory used by a roaring array, but does not free the containers
 */
static void ra_clear_without_containers(roaring_array_t *r);

/**
 * Frees just the containers
 */
static void ra_clear_containers(roaring_array_t *ra);

/**
 * Get the index corresponding to a 16-bit key
 */
static inline int32_t ra_get_index(const roaring_array_t *ra, uint16_t x) {
    if ((ra->size == 0) || ra->keys[ra->size - 1] == x) return ra->size - 1;
    return binarySearch(ra->keys, (int32_t)ra->size, x);
}

/**
 * Retrieves the container at index i, filling in the typecode
 */
static inline container_t *ra_get_container_at_index(
    const roaring_array_t *ra, uint16_t i, uint8_t *typecode
){
    *typecode = ra->typecodes[i];
    return ra->containers[i];
}

/**
 * Retrieves the key at index i
 */
static uint16_t ra_get_key_at_index(const roaring_array_t *ra, uint16_t i);

/**
 * Add a new key-value pair at index i
 */
static void ra_insert_new_key_value_at(
        roaring_array_t *ra, int32_t i, uint16_t key,
        container_t *c, uint8_t typecode);

/**
 * Append a new key-value pair
 */
static void ra_append(
        roaring_array_t *ra, uint16_t key,
        container_t *c, uint8_t typecode);

/**
 * Append a new key-value pair to ra, cloning (in COW sense) a value from sa
 * at index index
 */
static void ra_append_copy(roaring_array_t *ra, const roaring_array_t *sa,
                    uint16_t index, bool copy_on_write);

/**
 * Append new key-value pairs to ra, cloning (in COW sense)  values from sa
 * at indexes
 * [start_index, end_index)
 */
static void ra_append_copy_range(roaring_array_t *ra, const roaring_array_t *sa,
                          int32_t start_index, int32_t end_index,
                          bool copy_on_write);

/** appends from sa to ra, ending with the greatest key that is
 * is less or equal stopping_key
 */
static void ra_append_copies_until(roaring_array_t *ra, const roaring_array_t *sa,
                            uint16_t stopping_key, bool copy_on_write);

/** appends from sa to ra, starting with the smallest key that is
 * is strictly greater than before_start
 */

static void ra_append_copies_after(roaring_array_t *ra, const roaring_array_t *sa,
                            uint16_t before_start, bool copy_on_write);

/**
 * Move the key-value pairs to ra from sa at indexes
 * [start_index, end_index), old array should not be freed
 * (use ra_clear_without_containers)
 **/
static void ra_append_move_range(roaring_array_t *ra, roaring_array_t *sa,
                          int32_t start_index, int32_t end_index);
/**
 * Append new key-value pairs to ra,  from sa at indexes
 * [start_index, end_index)
 */
static void ra_append_range(roaring_array_t *ra, roaring_array_t *sa,
                     int32_t start_index, int32_t end_index,
                     bool copy_on_write);

/**
 * Set the container at the corresponding index using the specified
 * typecode.
 */
static inline void ra_set_container_at_index(
    const roaring_array_t *ra, int32_t i,
    container_t *c, uint8_t typecode
){
    assert(i < ra->size);
    ra->containers[i] = c;
    ra->typecodes[i] = typecode;
}

/**
 * If needed, increase the capacity of the array so that it can fit k values
 * (at
 * least);
 */
static bool extend_array(roaring_array_t *ra, int32_t k);

static inline int32_t ra_get_size(const roaring_array_t *ra) { return ra->size; }

static inline int32_t ra_advance_until(const roaring_array_t *ra, uint16_t x,
                                       int32_t pos) {
    return advanceUntil(ra->keys, pos, ra->size, x);
}

static int32_t ra_advance_until_freeing(roaring_array_t *ra, uint16_t x, int32_t pos);

static void ra_downsize(roaring_array_t *ra, int32_t new_length);

static inline void ra_replace_key_and_container_at_index(
    roaring_array_t *ra, int32_t i, uint16_t key,
    container_t *c, uint8_t typecode
){
    assert(i < ra->size);

    ra->keys[i] = key;
    ra->containers[i] = c;
    ra->typecodes[i] = typecode;
}

// write set bits to an array
static void ra_to_uint32_array(const roaring_array_t *ra, uint32_t *ans);

static bool ra_range_uint32_array(const roaring_array_t *ra, size_t offset, size_t limit, uint32_t *ans);

/**
 * write a bitmap to a buffer. This is meant to be compatible with
 * the
 * Java and Go versions. Return the size in bytes of the serialized
 * output (which should be ra_portable_size_in_bytes(ra)).
 */
static size_t ra_portable_serialize(const roaring_array_t *ra, char *buf);

/**
 * read a bitmap from a serialized version. This is meant to be compatible
 * with the Java and Go versions.
 * maxbytes  indicates how many bytes available from buf.
 * When the function returns true, roaring_array_t is populated with the data
 * and *readbytes indicates how many bytes were read. In all cases, if the function
 * returns true, then maxbytes >= *readbytes.
 */
static bool ra_portable_deserialize(roaring_array_t *ra, const char *buf, const size_t maxbytes, size_t * readbytes);

/**
 * Quickly checks whether there is a serialized bitmap at the pointer,
 * not exceeding size "maxbytes" in bytes. This function does not allocate
 * memory dynamically.
 *
 * This function returns 0 if and only if no valid bitmap is found.
 * Otherwise, it returns how many bytes are occupied by the bitmap data.
 */
static size_t ra_portable_deserialize_size(const char *buf, const size_t maxbytes);

/**
 * How many bytes are required to serialize this bitmap (meant to be
 * compatible
 * with Java and Go versions)
 */
static size_t ra_portable_size_in_bytes(const roaring_array_t *ra);

/**
 * return true if it contains at least one run container.
 */
static bool ra_has_run_container(const roaring_array_t *ra);

/**
 * Size of the header when serializing (meant to be compatible
 * with Java and Go versions)
 */
static uint32_t ra_portable_header_size(const roaring_array_t *ra);

/**
 * If the container at the index i is share, unshare it (creating a local
 * copy if needed).
 */
static inline void ra_unshare_container_at_index(roaring_array_t *ra,
                                                 uint16_t i) {
    assert(i < ra->size);
    ra->containers[i] = get_writable_copy_if_shared(ra->containers[i],
                                                    &ra->typecodes[i]);
}

/**
 * remove at index i, sliding over all entries after i
 */
static void ra_remove_at_index(roaring_array_t *ra, int32_t i);


/**
* clears all containers, sets the size at 0 and shrinks the memory usage.
*/
static void ra_reset(roaring_array_t *ra);

/**
 * remove at index i, sliding over all entries after i. Free removed container.
 */
static void ra_remove_at_index_and_free(roaring_array_t *ra, int32_t i);

/**
 * remove a chunk of indices, sliding over entries after it
 */
// void ra_remove_index_range(roaring_array_t *ra, int32_t begin, int32_t end);

// used in inplace andNot only, to slide left the containers from
// the mutated RoaringBitmap that are after the largest container of
// the argument RoaringBitmap.  It is followed by a call to resize.
//
static void ra_copy_range(roaring_array_t *ra, uint32_t begin, uint32_t end,
                   uint32_t new_begin);

/**
 * Shifts rightmost $count containers to the left (distance < 0) or
 * to the right (distance > 0).
 * Allocates memory if necessary.
 * This function doesn't free or create new containers.
 * Caller is responsible for that.
 */
static void ra_shift_tail(roaring_array_t *ra, int32_t count, int32_t distance);

#ifdef __cplusplus
}  // namespace internal
} }  // extern "C" { namespace roaring {
#endif

#endif
/* end file include/roaring/roaring_array.h */
/* begin file include/roaring/misc/configreport.h */
/*
 * configreport.h
 *
 */

#ifndef INCLUDE_MISC_CONFIGREPORT_H_
#define INCLUDE_MISC_CONFIGREPORT_H_

#include <stddef.h>  // for size_t
#include <stdint.h>
#include <stdio.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace misc {
#endif

#ifdef CROARING_IS_X64
// useful for basic info (0)
static inline void native_cpuid(unsigned int *eax, unsigned int *ebx,
                                unsigned int *ecx, unsigned int *edx) {
#ifdef ROARING_INLINE_ASM
    __asm volatile("cpuid"
                   : "=a"(*eax), "=b"(*ebx), "=c"(*ecx), "=d"(*edx)
                   : "0"(*eax), "2"(*ecx));
#endif /* not sure what to do when static inline assembly is unavailable*/
}

// CPUID instruction takes no parameters as CPUID implicitly uses the EAX
// register.
// The EAX register should be loaded with a value specifying what information to
// return
static inline void cpuinfo(int code, int *eax, int *ebx, int *ecx, int *edx) {
#ifdef ROARING_INLINE_ASM
    __asm__ volatile("cpuid;"  //  call cpuid instruction
                     : "=a"(*eax), "=b"(*ebx), "=c"(*ecx),
                       "=d"(*edx)  // output equal to "movl  %%eax %1"
                     : "a"(code)   // input equal to "movl %1, %%eax"
                     //:"%eax","%ebx","%ecx","%edx"// clobbered register
                     );
#endif /* not sure what to do when static inline assembly is unavailable*/
}

static inline int computecacheline() {
    int eax = 0, ebx = 0, ecx = 0, edx = 0;
    cpuinfo((int)0x80000006, &eax, &ebx, &ecx, &edx);
    return ecx & 0xFF;
}

// this is quite imperfect, but can be handy
static inline const char *guessprocessor() {
    unsigned eax = 1, ebx = 0, ecx = 0, edx = 0;
    native_cpuid(&eax, &ebx, &ecx, &edx);
    const char *codename;
    switch (eax >> 4) {
        case 0x506E:
            codename = "Skylake";
            break;
        case 0x406C:
            codename = "CherryTrail";
            break;
        case 0x306D:
            codename = "Broadwell";
            break;
        case 0x306C:
            codename = "Haswell";
            break;
        case 0x306A:
            codename = "IvyBridge";
            break;
        case 0x206A:
        case 0x206D:
            codename = "SandyBridge";
            break;
        case 0x2065:
        case 0x206C:
        case 0x206F:
            codename = "Westmere";
            break;
        case 0x106E:
        case 0x106A:
        case 0x206E:
            codename = "Nehalem";
            break;
        case 0x1067:
        case 0x106D:
            codename = "Penryn";
            break;
        case 0x006F:
        case 0x1066:
            codename = "Merom";
            break;
        case 0x0066:
            codename = "Presler";
            break;
        case 0x0063:
        case 0x0064:
            codename = "Prescott";
            break;
        case 0x006D:
            codename = "Dothan";
            break;
        case 0x0366:
            codename = "Cedarview";
            break;
        case 0x0266:
            codename = "Lincroft";
            break;
        case 0x016C:
            codename = "Pineview";
            break;
        default:
            codename = "UNKNOWN";
            break;
    }
    return codename;
}

static inline void tellmeall() {
    printf("x64 processor:  %s\t", guessprocessor());

#ifdef __VERSION__
    printf(" compiler version: %s\t", __VERSION__);
#endif
    uint32_t config =  croaring_detect_supported_architectures();
    if((config & CROARING_NEON) == CROARING_NEON) {
        printf(" NEON detected\t");
    }
 #ifdef __AVX2__
    printf(" Building for AVX2\t");
 #endif
    if(croaring_avx2()) {
        printf( "AVX2 usable\t");
    }
    if((config & CROARING_AVX2) == CROARING_AVX2) {
        printf( "AVX2 detected\t");
       if(!croaring_avx2()) {
         printf( "AVX2 not used\t");
       }
     }
    if((config & CROARING_SSE42) == CROARING_SSE42) {
        printf(" SSE4.2 detected\t");
    }
    if((config & CROARING_BMI1) == CROARING_BMI1) {
        printf(" BMI1 detected\t");
    }
    if((config & CROARING_BMI2) == CROARING_BMI2) {
        printf(" BMI2 detected\t");
    }
    printf("\n");
    if ((sizeof(int) != 4) || (sizeof(long) != 8)) {
        printf("number of bytes: int = %lu long = %lu \n",
               (long unsigned int)sizeof(size_t),
               (long unsigned int)sizeof(int));
    }
#ifdef __LITTLE_ENDIAN__
// This is what we expect!
// printf("you have little endian machine");
#endif
#ifdef __BIG_ENDIAN__
    printf("you have a big endian machine");
#endif
#ifdef __CHAR_BIT__
    if (__CHAR_BIT__ != 8) printf("on your machine, chars don't have 8bits???");
#endif
    if (computecacheline() != 64)
        printf("cache line: %d bytes\n", computecacheline());
}
#else

static inline void tellmeall() {
    printf("Non-X64  processor\n");
#ifdef __arm__
    printf("ARM processor detected\n");
#endif
#ifdef __VERSION__
    printf(" compiler version: %s\t", __VERSION__);
#endif
    uint32_t config =  croaring_detect_supported_architectures();
    if((config & CROARING_NEON) == CROARING_NEON) {
        printf(" NEON detected\t");
    }
    if((config & CROARING_ALTIVEC) == CROARING_ALTIVEC) {
        printf("Altivec detected\n");
    }

    if ((sizeof(int) != 4) || (sizeof(long) != 8)) {
        printf("number of bytes: int = %lu long = %lu \n",
               (long unsigned int)sizeof(size_t),
               (long unsigned int)sizeof(int));
    }
#ifdef __LITTLE_ENDIAN__
// This is what we expect!
// printf("you have little endian machine");
#endif
#ifdef __BIG_ENDIAN__
    printf("you have a big endian machine");
#endif
#ifdef __CHAR_BIT__
    if (__CHAR_BIT__ != 8) printf("on your machine, chars don't have 8bits???");
#endif
}

#endif

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace misc {
#endif

#endif /* INCLUDE_MISC_CONFIGREPORT_H_ */
/* end file include/roaring/misc/configreport.h */
/* begin file src/roaring_array.c */
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

// Convention: [0,ra->size) all elements are initialized
//  [ra->size, ra->allocation_size) is junk and contains nothing needing freeing

extern inline int32_t ra_get_size(const roaring_array_t *ra);
extern inline int32_t ra_get_index(const roaring_array_t *ra, uint16_t x);

extern inline container_t *ra_get_container_at_index(
    const roaring_array_t *ra, uint16_t i,
    uint8_t *typecode);

extern inline void ra_unshare_container_at_index(roaring_array_t *ra,
                                                 uint16_t i);

extern inline void ra_replace_key_and_container_at_index(
    roaring_array_t *ra, int32_t i, uint16_t key,
    container_t *c, uint8_t typecode);

extern inline void ra_set_container_at_index(
    const roaring_array_t *ra, int32_t i,
    container_t *c, uint8_t typecode);

static bool realloc_array(roaring_array_t *ra, int32_t new_capacity) {
    //
    // Note: not implemented using C's realloc(), because the memory layout is
    // Struct-of-Arrays vs. Array-of-Structs:
    // https://github.com/RoaringBitmap/CRoaring/issues/256

    if ( new_capacity == 0 ) {
      ndpi_free(ra->containers);
      ra->containers = NULL;
      ra->keys = NULL;
      ra->typecodes = NULL;
      ra->allocation_size = 0;
      return true;
    }
    const size_t memoryneeded = new_capacity * (
                sizeof(uint16_t) + sizeof(container_t *) + sizeof(uint8_t));
    void *bigalloc = ndpi_malloc(memoryneeded);
    if (!bigalloc) return false;
    void *oldbigalloc = ra->containers;
    container_t **newcontainers = (container_t **)bigalloc;
    uint16_t *newkeys = (uint16_t *)(newcontainers + new_capacity);
    uint8_t *newtypecodes = (uint8_t *)(newkeys + new_capacity);
    assert((char *)(newtypecodes + new_capacity) ==
           (char *)bigalloc + memoryneeded);
    if(ra->size > 0) {
      memcpy(newcontainers, ra->containers, sizeof(container_t *) * ra->size);
      memcpy(newkeys, ra->keys, sizeof(uint16_t) * ra->size);
      memcpy(newtypecodes, ra->typecodes, sizeof(uint8_t) * ra->size);
    }
    ra->containers = newcontainers;
    ra->keys = newkeys;
    ra->typecodes = newtypecodes;
    ra->allocation_size = new_capacity;
    ndpi_free(oldbigalloc);
    return true;
}

static bool ra_init_with_capacity(roaring_array_t *new_ra, uint32_t cap) {
    if (!new_ra) return false;
    ra_init(new_ra);

    if (cap > INT32_MAX) { return false; }

    if(cap > 0) {
      void *bigalloc = ndpi_malloc(cap *
                (sizeof(uint16_t) + sizeof(container_t *) + sizeof(uint8_t)));
      if( bigalloc == NULL ) return false;
      new_ra->containers = (container_t **)bigalloc;
      new_ra->keys = (uint16_t *)(new_ra->containers + cap);
      new_ra->typecodes = (uint8_t *)(new_ra->keys + cap);
      // Narrowing is safe because of above check
      new_ra->allocation_size = (int32_t)cap;
    }
    return true;
}

static int ra_shrink_to_fit(roaring_array_t *ra) {
    int savings = (ra->allocation_size - ra->size) *
                  (sizeof(uint16_t) + sizeof(container_t *) + sizeof(uint8_t));
    if (!realloc_array(ra, ra->size)) {
      return 0;
    }
    ra->allocation_size = ra->size;
    return savings;
}

static void ra_init(roaring_array_t *new_ra) {
    if (!new_ra) { return; }
    new_ra->keys = NULL;
    new_ra->containers = NULL;
    new_ra->typecodes = NULL;

    new_ra->allocation_size = 0;
    new_ra->size = 0;
    new_ra->flags = 0;
}

static bool ra_overwrite(const roaring_array_t *source, roaring_array_t *dest,
                  bool copy_on_write) {
    ra_clear_containers(dest);  // we are going to overwrite them
    if (source->size == 0) {  // Note: can't call memcpy(NULL), even w/size
        dest->size = 0; // <--- This is important.
        return true;  // output was just cleared, so they match
    }
    if (dest->allocation_size < source->size) {
        if (!realloc_array(dest, source->size)) {
            return false;
        }
    }
    dest->size = source->size;
    memcpy(dest->keys, source->keys, dest->size * sizeof(uint16_t));
    // we go through the containers, turning them into shared containers...
    if (copy_on_write) {
        int32_t i; for (i = 0; i < dest->size; ++i) {
            source->containers[i] = get_copy_of_container(
                source->containers[i], &source->typecodes[i], copy_on_write);
        }
        // we do a shallow copy to the other bitmap
        memcpy(dest->containers, source->containers,
               dest->size * sizeof(container_t *));
        memcpy(dest->typecodes, source->typecodes,
               dest->size * sizeof(uint8_t));
    } else {
        memcpy(dest->typecodes, source->typecodes,
               dest->size * sizeof(uint8_t));
        int32_t i; for (i = 0; i < dest->size; i++) {
            dest->containers[i] =
                container_clone(source->containers[i], source->typecodes[i]);
            if (dest->containers[i] == NULL) {
                int32_t j; for (j = 0; j < i; j++) {
                    container_free(dest->containers[j], dest->typecodes[j]);
                }
                ra_clear_without_containers(dest);
                return false;
            }
        }
    }
    return true;
}

static void ra_clear_containers(roaring_array_t *ra) {
    int32_t i; for (i = 0; i < ra->size; ++i) {
        container_free(ra->containers[i], ra->typecodes[i]);
    }
}

static void ra_reset(roaring_array_t *ra) {
  ra_clear_containers(ra);
  ra->size = 0;
  ra_shrink_to_fit(ra);
}

static void ra_clear_without_containers(roaring_array_t *ra) {
    ndpi_free(ra->containers);    // keys and typecodes are allocated with containers
    ra->size = 0;
    ra->allocation_size = 0;
    ra->containers = NULL;
    ra->keys = NULL;
    ra->typecodes = NULL;
}

static void ra_clear(roaring_array_t *ra) {
    ra_clear_containers(ra);
    ra_clear_without_containers(ra);
}

static bool extend_array(roaring_array_t *ra, int32_t k) {
    int32_t desired_size = ra->size + k;
    assert(desired_size <= MAX_CONTAINERS);
    if (desired_size > ra->allocation_size) {
        int32_t new_capacity =
            (ra->size < 1024) ? 2 * desired_size : 5 * desired_size / 4;
        if (new_capacity > MAX_CONTAINERS) {
            new_capacity = MAX_CONTAINERS;
        }

        return realloc_array(ra, new_capacity);
    }
    return true;
}

static void ra_append(
    roaring_array_t *ra, uint16_t key,
    container_t *c, uint8_t typecode
){
    extend_array(ra, 1);
    const int32_t pos = ra->size;

    ra->keys[pos] = key;
    ra->containers[pos] = c;
    ra->typecodes[pos] = typecode;
    ra->size++;
}

static void ra_append_copy(roaring_array_t *ra, const roaring_array_t *sa,
                    uint16_t index, bool copy_on_write) {
    extend_array(ra, 1);
    const int32_t pos = ra->size;

    // old contents is junk not needing freeing
    ra->keys[pos] = sa->keys[index];
    // the shared container will be in two bitmaps
    if (copy_on_write) {
        sa->containers[index] = get_copy_of_container(
            sa->containers[index], &sa->typecodes[index], copy_on_write);
        ra->containers[pos] = sa->containers[index];
        ra->typecodes[pos] = sa->typecodes[index];
    } else {
        ra->containers[pos] =
            container_clone(sa->containers[index], sa->typecodes[index]);
        ra->typecodes[pos] = sa->typecodes[index];
    }
    ra->size++;
}

static void ra_append_copies_until(roaring_array_t *ra, const roaring_array_t *sa,
                            uint16_t stopping_key, bool copy_on_write) {
    int32_t i; for (i = 0; i < sa->size; ++i) {
        if (sa->keys[i] >= stopping_key) break;
        ra_append_copy(ra, sa, i, copy_on_write);
    }
}

static void ra_append_copy_range(roaring_array_t *ra, const roaring_array_t *sa,
                          int32_t start_index, int32_t end_index,
                          bool copy_on_write) {
    extend_array(ra, end_index - start_index);
    int32_t i; for (i = start_index; i < end_index; ++i) {
        const int32_t pos = ra->size;
        ra->keys[pos] = sa->keys[i];
        if (copy_on_write) {
            sa->containers[i] = get_copy_of_container(
                sa->containers[i], &sa->typecodes[i], copy_on_write);
            ra->containers[pos] = sa->containers[i];
            ra->typecodes[pos] = sa->typecodes[i];
        } else {
            ra->containers[pos] =
                container_clone(sa->containers[i], sa->typecodes[i]);
            ra->typecodes[pos] = sa->typecodes[i];
        }
        ra->size++;
    }
}

static void ra_append_copies_after(roaring_array_t *ra, const roaring_array_t *sa,
                            uint16_t before_start, bool copy_on_write) {
    int start_location = ra_get_index(sa, before_start);
    if (start_location >= 0)
        ++start_location;
    else
        start_location = -start_location - 1;
    ra_append_copy_range(ra, sa, start_location, sa->size, copy_on_write);
}

static void ra_append_move_range(roaring_array_t *ra, roaring_array_t *sa,
                          int32_t start_index, int32_t end_index) {
    extend_array(ra, end_index - start_index);

    int32_t i; for (i = start_index; i < end_index; ++i) {
        const int32_t pos = ra->size;

        ra->keys[pos] = sa->keys[i];
        ra->containers[pos] = sa->containers[i];
        ra->typecodes[pos] = sa->typecodes[i];
        ra->size++;
    }
}

static void ra_append_range(roaring_array_t *ra, roaring_array_t *sa,
                     int32_t start_index, int32_t end_index,
                     bool copy_on_write) {
    extend_array(ra, end_index - start_index);

    int32_t i; for (i = start_index; i < end_index; ++i) {
        const int32_t pos = ra->size;
        ra->keys[pos] = sa->keys[i];
        if (copy_on_write) {
            sa->containers[i] = get_copy_of_container(
                sa->containers[i], &sa->typecodes[i], copy_on_write);
            ra->containers[pos] = sa->containers[i];
            ra->typecodes[pos] = sa->typecodes[i];
        } else {
            ra->containers[pos] =
                container_clone(sa->containers[i], sa->typecodes[i]);
            ra->typecodes[pos] = sa->typecodes[i];
        }
        ra->size++;
    }
}

static container_t *ra_get_container(
    roaring_array_t *ra, uint16_t x, uint8_t *typecode
){
    int i = binarySearch(ra->keys, (int32_t)ra->size, x);
    if (i < 0) return NULL;
    *typecode = ra->typecodes[i];
    return ra->containers[i];
}

extern inline container_t *ra_get_container_at_index(
    const roaring_array_t *ra, uint16_t i,
    uint8_t *typecode);

#ifdef ROARING_NOT_USED
static container_t *ra_get_writable_container(
    roaring_array_t *ra, uint16_t x,
    uint8_t *typecode
){
    int i = binarySearch(ra->keys, (int32_t)ra->size, x);
    if (i < 0) return NULL;
    *typecode = ra->typecodes[i];
    return get_writable_copy_if_shared(ra->containers[i], typecode);
}

static container_t *ra_get_writable_container_at_index(
    roaring_array_t *ra, uint16_t i,
    uint8_t *typecode
){
    assert(i < ra->size);
    *typecode = ra->typecodes[i];
    return get_writable_copy_if_shared(ra->containers[i], typecode);
}
#endif

static uint16_t ra_get_key_at_index(const roaring_array_t *ra, uint16_t i) {
    return ra->keys[i];
}

extern inline int32_t ra_get_index(const roaring_array_t *ra, uint16_t x);

extern inline int32_t ra_advance_until(const roaring_array_t *ra, uint16_t x,
                                int32_t pos);

// everything skipped over is freed
static int32_t ra_advance_until_freeing(roaring_array_t *ra, uint16_t x, int32_t pos) {
    while (pos < ra->size && ra->keys[pos] < x) {
        container_free(ra->containers[pos], ra->typecodes[pos]);
        ++pos;
    }
    return pos;
}

static void ra_insert_new_key_value_at(
    roaring_array_t *ra, int32_t i, uint16_t key,
    container_t *c, uint8_t typecode
){
    extend_array(ra, 1);
    // May be an optimization opportunity with DIY memmove
    memmove(&(ra->keys[i + 1]), &(ra->keys[i]),
            sizeof(uint16_t) * (ra->size - i));
    memmove(&(ra->containers[i + 1]), &(ra->containers[i]),
            sizeof(container_t *) * (ra->size - i));
    memmove(&(ra->typecodes[i + 1]), &(ra->typecodes[i]),
            sizeof(uint8_t) * (ra->size - i));
    ra->keys[i] = key;
    ra->containers[i] = c;
    ra->typecodes[i] = typecode;
    ra->size++;
}

// note: Java routine set things to 0, enabling GC.
// Java called it "resize" but it was always used to downsize.
// Allowing upsize would break the conventions about
// valid containers below ra->size.

static void ra_downsize(roaring_array_t *ra, int32_t new_length) {
    assert(new_length <= ra->size);
    ra->size = new_length;
}

static void ra_remove_at_index(roaring_array_t *ra, int32_t i) {
    memmove(&(ra->containers[i]), &(ra->containers[i + 1]),
            sizeof(container_t *) * (ra->size - i - 1));
    memmove(&(ra->keys[i]), &(ra->keys[i + 1]),
            sizeof(uint16_t) * (ra->size - i - 1));
    memmove(&(ra->typecodes[i]), &(ra->typecodes[i + 1]),
            sizeof(uint8_t) * (ra->size - i - 1));
    ra->size--;
}

static void ra_remove_at_index_and_free(roaring_array_t *ra, int32_t i) {
    container_free(ra->containers[i], ra->typecodes[i]);
    ra_remove_at_index(ra, i);
}

// used in inplace andNot only, to slide left the containers from
// the mutated RoaringBitmap that are after the largest container of
// the argument RoaringBitmap.  In use it should be followed by a call to
// downsize.
//
static void ra_copy_range(roaring_array_t *ra, uint32_t begin, uint32_t end,
                   uint32_t new_begin) {
    assert(begin <= end);
    assert(new_begin < begin);

    const int range = end - begin;

    // We ensure to previously have freed overwritten containers
    // that are not copied elsewhere

    memmove(&(ra->containers[new_begin]), &(ra->containers[begin]),
            sizeof(container_t *) * range);
    memmove(&(ra->keys[new_begin]), &(ra->keys[begin]),
            sizeof(uint16_t) * range);
    memmove(&(ra->typecodes[new_begin]), &(ra->typecodes[begin]),
            sizeof(uint8_t) * range);
}

static void ra_shift_tail(roaring_array_t *ra, int32_t count, int32_t distance) {
    if (distance > 0) {
        extend_array(ra, distance);
    }
    int32_t srcpos = ra->size - count;
    int32_t dstpos = srcpos + distance;
    memmove(&(ra->keys[dstpos]), &(ra->keys[srcpos]),
            sizeof(uint16_t) * count);
    memmove(&(ra->containers[dstpos]), &(ra->containers[srcpos]),
            sizeof(container_t *) * count);
    memmove(&(ra->typecodes[dstpos]), &(ra->typecodes[srcpos]),
            sizeof(uint8_t) * count);
    ra->size += distance;
}


static void ra_to_uint32_array(const roaring_array_t *ra, uint32_t *ans) {
    size_t ctr = 0;
    int32_t i; for (i = 0; i < ra->size; ++i) {
        int num_added = container_to_uint32_array(
            ans + ctr, ra->containers[i], ra->typecodes[i],
            ((uint32_t)ra->keys[i]) << 16);
        ctr += num_added;
    }
}

static bool ra_range_uint32_array(const roaring_array_t *ra, size_t offset, size_t limit, uint32_t *ans) {
    size_t ctr = 0;
    size_t dtr = 0;

    size_t t_limit = 0;

    bool first = false;
    size_t first_skip = 0;

    uint32_t *t_ans = NULL;
    size_t cur_len = 0;

    int i = 0; for (i = 0; i < ra->size; ++i) {

        const container_t *c = container_unwrap_shared(
                                        ra->containers[i], &ra->typecodes[i]);
        switch (ra->typecodes[i]) {
            case BITSET_CONTAINER_TYPE:
                t_limit = (const_CAST_bitset(c))->cardinality;
                break;
            case ARRAY_CONTAINER_TYPE:
                t_limit = (const_CAST_array(c))->cardinality;
                break;
            case RUN_CONTAINER_TYPE:
                t_limit = run_container_cardinality(const_CAST_run(c));
                break;
        }
        if (ctr + t_limit - 1 >= offset && ctr < offset + limit){
            if (!first){
                //first_skip = t_limit - (ctr + t_limit - offset);
                first_skip = offset - ctr;
                first = true;
                t_ans = (uint32_t *)ndpi_malloc(sizeof(*t_ans) * (first_skip + limit));
                if(t_ans == NULL) {
                  return false;
                }
                memset(t_ans, 0, sizeof(*t_ans) * (first_skip + limit)) ;
                cur_len = first_skip + limit;
            }
            if (dtr + t_limit > cur_len){
                uint32_t * append_ans = (uint32_t *)ndpi_malloc(sizeof(*append_ans) * (cur_len + t_limit));
                if(append_ans == NULL) {
                  if(t_ans != NULL) ndpi_free(t_ans);
                  return false;
                }
                memset(append_ans, 0, sizeof(*append_ans) * (cur_len + t_limit));
                cur_len = cur_len + t_limit;
                memcpy(append_ans, t_ans, dtr * sizeof(uint32_t));
                ndpi_free(t_ans);
                t_ans = append_ans;
            }
            switch (ra->typecodes[i]) {
                case BITSET_CONTAINER_TYPE:
                    container_to_uint32_array(
                        t_ans + dtr,
                        const_CAST_bitset(c),  ra->typecodes[i],
                        ((uint32_t)ra->keys[i]) << 16);
                    break;
                case ARRAY_CONTAINER_TYPE:
                    container_to_uint32_array(
                        t_ans + dtr,
                        const_CAST_array(c), ra->typecodes[i],
                        ((uint32_t)ra->keys[i]) << 16);
                    break;
                case RUN_CONTAINER_TYPE:
                    container_to_uint32_array(
                        t_ans + dtr,
                        const_CAST_run(c), ra->typecodes[i],
                        ((uint32_t)ra->keys[i]) << 16);
                    break;
            }
            dtr += t_limit;
        }
        ctr += t_limit;
        if (dtr-first_skip >= limit) break;
    }
    if(t_ans != NULL) {
      memcpy(ans, t_ans+first_skip, limit * sizeof(uint32_t));
      ndpi_free(t_ans);
    }
    return true;
}

static bool ra_has_run_container(const roaring_array_t *ra) {
    int32_t k; for (k = 0; k < ra->size; ++k) {
        if (get_container_type(ra->containers[k], ra->typecodes[k]) ==
            RUN_CONTAINER_TYPE)
            return true;
    }
    return false;
}

static uint32_t ra_portable_header_size(const roaring_array_t *ra) {
    if (ra_has_run_container(ra)) {
        if (ra->size <
            NO_OFFSET_THRESHOLD) {  // for small bitmaps, we omit the offsets
            return 4 + (ra->size + 7) / 8 + 4 * ra->size;
        }
        return 4 + (ra->size + 7) / 8 +
               8 * ra->size;  // - 4 because we pack the size with the cookie
    } else {
        return 4 + 4 + 8 * ra->size;
    }
}

static size_t ra_portable_size_in_bytes(const roaring_array_t *ra) {
    size_t count = ra_portable_header_size(ra);

    int32_t k; for (k = 0; k < ra->size; ++k) {
        count += container_size_in_bytes(ra->containers[k], ra->typecodes[k]);
    }
    return count;
}

static size_t ra_portable_serialize(const roaring_array_t *ra, char *buf) {
    char *initbuf = buf;
    uint32_t startOffset = 0;
    bool hasrun = ra_has_run_container(ra);
    if (hasrun) {
        uint32_t cookie = SERIAL_COOKIE | ((ra->size - 1) << 16);
        memcpy(buf, &cookie, sizeof(cookie));
        buf += sizeof(cookie);
        uint32_t s = (ra->size + 7) / 8;
        uint8_t *bitmapOfRunContainers = (uint8_t *)ndpi_calloc(s, 1);
        assert(bitmapOfRunContainers != NULL);  // todo: handle
        int32_t i; for (i = 0; i < ra->size; ++i) {
            if (get_container_type(ra->containers[i], ra->typecodes[i]) ==
                RUN_CONTAINER_TYPE) {
                bitmapOfRunContainers[i / 8] |= (1 << (i % 8));
            }
        }
        memcpy(buf, bitmapOfRunContainers, s);
        buf += s;
        ndpi_free(bitmapOfRunContainers);
        if (ra->size < NO_OFFSET_THRESHOLD) {
            startOffset = 4 + 4 * ra->size + s;
        } else {
            startOffset = 4 + 8 * ra->size + s;
        }
    } else {  // backwards compatibility
        uint32_t cookie = SERIAL_COOKIE_NO_RUNCONTAINER;

        memcpy(buf, &cookie, sizeof(cookie));
        buf += sizeof(cookie);
        memcpy(buf, &ra->size, sizeof(ra->size));
        buf += sizeof(ra->size);

        startOffset = 4 + 4 + 4 * ra->size + 4 * ra->size;
    }
    int32_t k; for (k = 0; k < ra->size; ++k) {
        memcpy(buf, &ra->keys[k], sizeof(ra->keys[k]));
        buf += sizeof(ra->keys[k]);
        // get_cardinality returns a value in [1,1<<16], subtracting one
        // we get [0,1<<16 - 1] which fits in 16 bits
        uint16_t card = (uint16_t)(
            container_get_cardinality(ra->containers[k], ra->typecodes[k]) - 1);
        memcpy(buf, &card, sizeof(card));
        buf += sizeof(card);
    }
    if ((!hasrun) || (ra->size >= NO_OFFSET_THRESHOLD)) {
        // writing the containers offsets
        int32_t k; for (k = 0; k < ra->size; k++) {
            memcpy(buf, &startOffset, sizeof(startOffset));
            buf += sizeof(startOffset);
            startOffset =
                startOffset +
                container_size_in_bytes(ra->containers[k], ra->typecodes[k]);
        }
    }
    for (k = 0; k < ra->size; ++k) {
        buf += container_write(ra->containers[k], ra->typecodes[k], buf);
    }
    return buf - initbuf;
}

// Quickly checks whether there is a serialized bitmap at the pointer,
// not exceeding size "maxbytes" in bytes. This function does not allocate
// memory dynamically.
//
// This function returns 0 if and only if no valid bitmap is found.
// Otherwise, it returns how many bytes are occupied.
//
static size_t ra_portable_deserialize_size(const char *buf, const size_t maxbytes) {
    size_t bytestotal = sizeof(int32_t);// for cookie
    if(bytestotal > maxbytes) return 0;
    uint32_t cookie;
    memcpy(&cookie, buf, sizeof(int32_t));
    buf += sizeof(uint32_t);
    if ((cookie & 0xFFFF) != SERIAL_COOKIE &&
        cookie != SERIAL_COOKIE_NO_RUNCONTAINER) {
        return 0;
    }
    int32_t size;

    if ((cookie & 0xFFFF) == SERIAL_COOKIE)
        size = (cookie >> 16) + 1;
    else {
        bytestotal += sizeof(int32_t);
        if(bytestotal > maxbytes) return 0;
        memcpy(&size, buf, sizeof(int32_t));
        buf += sizeof(uint32_t);
    }
    if (size > (1<<16)) {
       return 0; // logically impossible
    }
    char *bitmapOfRunContainers = NULL;
    bool hasrun = (cookie & 0xFFFF) == SERIAL_COOKIE;
    if (hasrun) {
        int32_t s = (size + 7) / 8;
        bytestotal += s;
        if(bytestotal > maxbytes) return 0;
        bitmapOfRunContainers = (char *)buf;
        buf += s;
    }
    bytestotal += size * 2 * sizeof(uint16_t);
    if(bytestotal > maxbytes) return 0;
    uint16_t *keyscards = (uint16_t *)buf;
    buf += size * 2 * sizeof(uint16_t);
    if ((!hasrun) || (size >= NO_OFFSET_THRESHOLD)) {
        // skipping the offsets
        bytestotal += size * 4;
        if(bytestotal > maxbytes) return 0;
        buf += size * 4;
    }
    // Reading the containers
    int32_t k; for (k = 0; k < size; ++k) {
        uint16_t tmp;
        memcpy(&tmp, keyscards + 2*k+1, sizeof(tmp));
        uint32_t thiscard = tmp + 1;
        bool isbitmap = (thiscard > DEFAULT_MAX_SIZE);
        bool isrun = false;
        if(hasrun) {
          if((bitmapOfRunContainers[k / 8] & (1 << (k % 8))) != 0) {
            isbitmap = false;
            isrun = true;
          }
        }
        if (isbitmap) {
            size_t containersize = BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);
            bytestotal += containersize;
            if(bytestotal > maxbytes) return 0;
            buf += containersize;
        } else if (isrun) {
            bytestotal += sizeof(uint16_t);
            if(bytestotal > maxbytes) return 0;
            uint16_t n_runs;
            memcpy(&n_runs, buf, sizeof(uint16_t));
            buf += sizeof(uint16_t);
            size_t containersize = n_runs * sizeof(rle16_t);
            bytestotal += containersize;
            if(bytestotal > maxbytes) return 0;
            buf += containersize;
        } else {
            size_t containersize = thiscard * sizeof(uint16_t);
            bytestotal += containersize;
            if(bytestotal > maxbytes) return 0;
            buf += containersize;
        }
    }
    return bytestotal;
}


// this function populates answer from the content of buf (reading up to maxbytes bytes).
// The function returns false if a properly serialized bitmap cannot be found.
// if it returns true, readbytes is populated by how many bytes were read, we have that *readbytes <= maxbytes.
static bool ra_portable_deserialize(roaring_array_t *answer, const char *buf, const size_t maxbytes, size_t * readbytes) {
    *readbytes = sizeof(int32_t);// for cookie
    if(*readbytes > maxbytes) {
      fprintf(stderr, "Ran out of bytes while reading first 4 bytes.\n");
      return false;
    }
    uint32_t cookie;
    memcpy(&cookie, buf, sizeof(int32_t));
    buf += sizeof(uint32_t);
    if ((cookie & 0xFFFF) != SERIAL_COOKIE &&
        cookie != SERIAL_COOKIE_NO_RUNCONTAINER) {
        fprintf(stderr, "I failed to find one of the right cookies. Found %" PRIu32 "\n",
                cookie);
        return false;
    }
    int32_t size;

    if ((cookie & 0xFFFF) == SERIAL_COOKIE)
        size = (cookie >> 16) + 1;
    else {
        *readbytes += sizeof(int32_t);
        if(*readbytes > maxbytes) {
          fprintf(stderr, "Ran out of bytes while reading second part of the cookie.\n");
          return false;
        }
        memcpy(&size, buf, sizeof(int32_t));
        buf += sizeof(uint32_t);
    }
    if (size > (1<<16)) {
       fprintf(stderr, "You cannot have so many containers, the data must be corrupted: %" PRId32 "\n",
                size);
       return false; // logically impossible
    }
    const char *bitmapOfRunContainers = NULL;
    bool hasrun = (cookie & 0xFFFF) == SERIAL_COOKIE;
    if (hasrun) {
        int32_t s = (size + 7) / 8;
        *readbytes += s;
        if(*readbytes > maxbytes) {// data is corrupted?
          fprintf(stderr, "Ran out of bytes while reading run bitmap.\n");
          return false;
        }
        bitmapOfRunContainers = buf;
        buf += s;
    }
    uint16_t *keyscards = (uint16_t *)buf;

    *readbytes += size * 2 * sizeof(uint16_t);
    if(*readbytes > maxbytes) {
      fprintf(stderr, "Ran out of bytes while reading key-cardinality array.\n");
      return false;
    }
    buf += size * 2 * sizeof(uint16_t);

    bool is_ok = ra_init_with_capacity(answer, size);
    if (!is_ok) {
        fprintf(stderr, "Failed to allocate memory for roaring array. Bailing out.\n");
        return false;
    }

    int32_t k; for (k = 0; k < size; ++k) {
        uint16_t tmp;
        memcpy(&tmp, keyscards + 2*k, sizeof(tmp));
        answer->keys[k] = tmp;
    }
    if ((!hasrun) || (size >= NO_OFFSET_THRESHOLD)) {
        *readbytes += size * 4;
        if(*readbytes > maxbytes) {// data is corrupted?
          fprintf(stderr, "Ran out of bytes while reading offsets.\n");
          ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
          return false;
        }

        // skipping the offsets
        buf += size * 4;
    }
    // Reading the containers
    for (k = 0; k < size; ++k) {
        uint16_t tmp;
        memcpy(&tmp, keyscards + 2*k+1, sizeof(tmp));
        uint32_t thiscard = tmp + 1;
        bool isbitmap = (thiscard > DEFAULT_MAX_SIZE);
        bool isrun = false;
        if(hasrun) {
          if((bitmapOfRunContainers[k / 8] & (1 << (k % 8))) != 0) {
            isbitmap = false;
            isrun = true;
          }
        }
        if (isbitmap) {
            // we check that the read is allowed
            size_t containersize = BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);
            *readbytes += containersize;
            if(*readbytes > maxbytes) {
              fprintf(stderr, "Running out of bytes while reading a bitset container.\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            // it is now safe to read
            bitset_container_t *c = bitset_container_create();
            if(c == NULL) {// memory allocation failure
              fprintf(stderr, "Failed to allocate memory for a bitset container.\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            answer->size++;
            buf += bitset_container_read(thiscard, c, buf);
            answer->containers[k] = c;
            answer->typecodes[k] = BITSET_CONTAINER_TYPE;
        } else if (isrun) {
            // we check that the read is allowed
            *readbytes += sizeof(uint16_t);
            if(*readbytes > maxbytes) {
              fprintf(stderr, "Running out of bytes while reading a run container (header).\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            uint16_t n_runs;
            memcpy(&n_runs, buf, sizeof(uint16_t));
            size_t containersize = n_runs * sizeof(rle16_t);
            *readbytes += containersize;
            if(*readbytes > maxbytes) {// data is corrupted?
              fprintf(stderr, "Running out of bytes while reading a run container.\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            // it is now safe to read

            run_container_t *c = run_container_create();
            if(c == NULL) {// memory allocation failure
              fprintf(stderr, "Failed to allocate memory for a run container.\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            answer->size++;
            buf += run_container_read(thiscard, c, buf);
            answer->containers[k] = c;
            answer->typecodes[k] = RUN_CONTAINER_TYPE;
        } else {
            // we check that the read is allowed
            size_t containersize = thiscard * sizeof(uint16_t);
            *readbytes += containersize;
            if(*readbytes > maxbytes) {// data is corrupted?
              fprintf(stderr, "Running out of bytes while reading an array container.\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            // it is now safe to read
            array_container_t *c =
                array_container_create_given_capacity(thiscard);
            if(c == NULL) {// memory allocation failure
              fprintf(stderr, "Failed to allocate memory for an array container.\n");
              ra_clear(answer);// we need to clear the containers already allocated, and the roaring array
              return false;
            }
            answer->size++;
            buf += array_container_read(thiscard, c, buf);
            answer->containers[k] = c;
            answer->typecodes[k] = ARRAY_CONTAINER_TYPE;
        }
    }
    return true;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/roaring_array.c */
/* begin file src/roaring_priority_queue.c */


#ifdef __cplusplus
using namespace ::roaring::internal;

extern "C" { namespace roaring { namespace api {
#endif

struct roaring_pq_element_s {
    uint64_t size;
    bool is_temporary;
    roaring_bitmap_t *bitmap;
};

typedef struct roaring_pq_element_s roaring_pq_element_t;

struct roaring_pq_s {
    roaring_pq_element_t *elements;
    uint64_t size;
};

typedef struct roaring_pq_s roaring_pq_t;

static inline bool compare(roaring_pq_element_t *t1, roaring_pq_element_t *t2) {
    return t1->size < t2->size;
}

static void pq_add(roaring_pq_t *pq, roaring_pq_element_t *t) {
    uint64_t i = pq->size;
    pq->elements[pq->size++] = *t;
    while (i > 0) {
        uint64_t p = (i - 1) >> 1;
        roaring_pq_element_t ap = pq->elements[p];
        if (!compare(t, &ap)) break;
        pq->elements[i] = ap;
        i = p;
    }
    pq->elements[i] = *t;
}

static void pq_free(roaring_pq_t *pq) {
    ndpi_free(pq);
}

static void percolate_down(roaring_pq_t *pq, uint32_t i) {
    uint32_t size = (uint32_t)pq->size;
    uint32_t hsize = size >> 1;
    roaring_pq_element_t ai = pq->elements[i];
    while (i < hsize) {
        uint32_t l = (i << 1) + 1;
        uint32_t r = l + 1;
        roaring_pq_element_t bestc = pq->elements[l];
        if (r < size) {
            if (compare(pq->elements + r, &bestc)) {
                l = r;
                bestc = pq->elements[r];
            }
        }
        if (!compare(&bestc, &ai)) {
            break;
        }
        pq->elements[i] = bestc;
        i = l;
    }
    pq->elements[i] = ai;
}

static roaring_pq_t *create_pq(const roaring_bitmap_t **arr, uint32_t length) {
    size_t alloc_size = sizeof(roaring_pq_t) + sizeof(roaring_pq_element_t) * length;
    roaring_pq_t *answer = (roaring_pq_t *)ndpi_malloc(alloc_size);
    answer->elements = (roaring_pq_element_t *)(answer + 1);
    answer->size = length;
    uint32_t i; for (i = 0; i < length; i++) {
        answer->elements[i].bitmap = (roaring_bitmap_t *)arr[i];
        answer->elements[i].is_temporary = false;
        answer->elements[i].size =
            roaring_bitmap_portable_size_in_bytes(arr[i]);
    }
    {
      int32_t i;
      for (i = (length >> 1); i >= 0; i--) {
        percolate_down(answer, i);
      }
    }
    return answer;
}

static roaring_pq_element_t pq_poll(roaring_pq_t *pq) {
    roaring_pq_element_t ans = *pq->elements;
    if (pq->size > 1) {
        pq->elements[0] = pq->elements[--pq->size];
        percolate_down(pq, 0);
    } else
        --pq->size;
    // memmove(pq->elements,pq->elements+1,(pq->size-1)*sizeof(roaring_pq_element_t));--pq->size;
    return ans;
}

// this function consumes and frees the inputs
static roaring_bitmap_t *lazy_or_from_lazy_inputs(roaring_bitmap_t *x1,
                                                  roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    const int length1 = ra_get_size(&x1->high_low_container),
              length2 = ra_get_size(&x2->high_low_container);
    if (0 == length1) {
        roaring_bitmap_free(x1);
        return x2;
    }
    if (0 == length2) {
        roaring_bitmap_free(x2);
        return x1;
    }
    uint32_t neededcap = length1 > length2 ? length2 : length1;
    roaring_bitmap_t *answer = roaring_bitmap_create_with_capacity(neededcap);
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            // todo: unsharing can be inefficient as it may create a clone where
            // none
            // is needed, but it has the benefit of being easy to reason about.

            ra_unshare_container_at_index(&x1->high_low_container, pos1);
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            assert(type1 != SHARED_CONTAINER_TYPE);

            ra_unshare_container_at_index(&x2->high_low_container, pos2);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            assert(type2 != SHARED_CONTAINER_TYPE);

            container_t *c;

            if ((type2 == BITSET_CONTAINER_TYPE) &&
                (type1 != BITSET_CONTAINER_TYPE)
            ){
                c = container_lazy_ior(c2, type2, c1, type1, &result_type);
                container_free(c1, type1);
                if (c != c2) {
                    container_free(c2, type2);
                }
            } else {
                c = container_lazy_ior(c1, type1, c2, type2, &result_type);
                container_free(c2, type2);
                if (c != c1) {
                    container_free(c1, type1);
                }
            }
            // since we assume that the initial containers are non-empty, the
            // result here
            // can only be non-empty
            ra_append(&answer->high_low_container, s1, c, result_type);
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            ra_append(&answer->high_low_container, s1, c1, type1);
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            ra_append(&answer->high_low_container, s2, c2, type2);
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_move_range(&answer->high_low_container,
                             &x2->high_low_container, pos2, length2);
    } else if (pos2 == length2) {
        ra_append_move_range(&answer->high_low_container,
                             &x1->high_low_container, pos1, length1);
    }
    ra_clear_without_containers(&x1->high_low_container);
    ra_clear_without_containers(&x2->high_low_container);
    ndpi_free(x1);
    ndpi_free(x2);
    return answer;
}

/**
 * Compute the union of 'number' bitmaps using a heap. This can
 * sometimes be faster than roaring_bitmap_or_many which uses
 * a naive algorithm. Caller is responsible for freeing the
 * result.
 */
roaring_bitmap_t *roaring_bitmap_or_many_heap(uint32_t number,
                                              const roaring_bitmap_t **x) {
    if (number == 0) {
        return roaring_bitmap_create();
    }
    if (number == 1) {
        return roaring_bitmap_copy(x[0]);
    }
    roaring_pq_t *pq = create_pq(x, number);
    while (pq->size > 1) {
        roaring_pq_element_t x1 = pq_poll(pq);
        roaring_pq_element_t x2 = pq_poll(pq);

        if (x1.is_temporary && x2.is_temporary) {
            roaring_bitmap_t *newb =
                lazy_or_from_lazy_inputs(x1.bitmap, x2.bitmap);
            // should normally return a fresh new bitmap *except* that
            // it can return x1.bitmap or x2.bitmap in degenerate cases
            bool temporary = !((newb == x1.bitmap) && (newb == x2.bitmap));
            uint64_t bsize = roaring_bitmap_portable_size_in_bytes(newb);
            roaring_pq_element_t newelement = {
                .size = bsize, .is_temporary = temporary, .bitmap = newb};
            pq_add(pq, &newelement);
        } else if (x2.is_temporary) {
            roaring_bitmap_lazy_or_inplace(x2.bitmap, x1.bitmap, false);
            x2.size = roaring_bitmap_portable_size_in_bytes(x2.bitmap);
            pq_add(pq, &x2);
        } else if (x1.is_temporary) {
            roaring_bitmap_lazy_or_inplace(x1.bitmap, x2.bitmap, false);
            x1.size = roaring_bitmap_portable_size_in_bytes(x1.bitmap);

            pq_add(pq, &x1);
        } else {
            roaring_bitmap_t *newb =
                roaring_bitmap_lazy_or(x1.bitmap, x2.bitmap, false);
            uint64_t bsize = roaring_bitmap_portable_size_in_bytes(newb);
            roaring_pq_element_t newelement = {
                .size = bsize, .is_temporary = true, .bitmap = newb};

            pq_add(pq, &newelement);
        }
    }
    roaring_pq_element_t X = pq_poll(pq);
    roaring_bitmap_t *answer = X.bitmap;
    roaring_bitmap_repair_after_lazy(answer);
    pq_free(pq);
    return answer;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace api {
#endif
/* end file src/roaring_priority_queue.c */
/* begin file src/roaring.c */
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>



#ifdef __cplusplus
using namespace ::roaring::internal;

extern "C" { namespace roaring { namespace api {
#endif

extern inline bool roaring_bitmap_contains(const roaring_bitmap_t *r,
                                           uint32_t val);
extern inline bool roaring_bitmap_get_copy_on_write(const roaring_bitmap_t* r);
extern inline void roaring_bitmap_set_copy_on_write(roaring_bitmap_t* r, bool cow);

static inline bool is_cow(const roaring_bitmap_t *r) {
    return r->high_low_container.flags & ROARING_FLAG_COW;
}
static inline bool is_frozen(const roaring_bitmap_t *r) {
    return r->high_low_container.flags & ROARING_FLAG_FROZEN;
}

// this is like roaring_bitmap_add, but it populates pointer arguments in such a
// way
// that we can recover the container touched, which, in turn can be used to
// accelerate some functions (when you repeatedly need to add to the same
// container)
static inline container_t *containerptr_roaring_bitmap_add(
    roaring_bitmap_t *r, uint32_t val,
    uint8_t *type, int *index
){
    roaring_array_t *ra = &r->high_low_container;

    uint16_t hb = val >> 16;
    const int i = ra_get_index(ra, hb);
    if (i >= 0) {
        ra_unshare_container_at_index(ra, i);
        container_t *c = ra_get_container_at_index(ra, i, type);
        uint8_t new_type = *type;
        container_t *c2 = container_add(c, val & 0xFFFF, *type, &new_type);
        *index = i;
        if (c2 != c) {
            container_free(c, *type);
            ra_set_container_at_index(ra, i, c2, new_type);
            *type = new_type;
            return c2;
        } else {
            return c;
        }
    } else {
        array_container_t *new_ac = array_container_create();
        container_t *c = container_add(new_ac, val & 0xFFFF,
                                       ARRAY_CONTAINER_TYPE, type);
        // we could just assume that it stays an array container
        ra_insert_new_key_value_at(ra, -i - 1, hb, c, *type);
        *index = -i - 1;
        return c;
    }
}

static roaring_bitmap_t *roaring_bitmap_create_with_capacity(uint32_t cap) {
    roaring_bitmap_t *ans =
        (roaring_bitmap_t *)ndpi_malloc(sizeof(roaring_bitmap_t));
    if (!ans) {
        return NULL;
    }
    bool is_ok = ra_init_with_capacity(&ans->high_low_container, cap);
    if (!is_ok) {
        ndpi_free(ans);
        return NULL;
    }
    return ans;
}

static bool roaring_bitmap_init_with_capacity(roaring_bitmap_t *r, uint32_t cap) {
    return ra_init_with_capacity(&r->high_low_container, cap);
}


static void roaring_bitmap_add_many(roaring_bitmap_t *r, size_t n_args,
                             const uint32_t *vals) {
    container_t *container = NULL;  // hold value of last container touched
    uint8_t typecode = 0;    // typecode of last container touched
    uint32_t prev = 0;       // previous valued inserted
    size_t i = 0;            // index of value
    int containerindex = 0;
    if (n_args == 0) return;
    uint32_t val;
    memcpy(&val, vals + i, sizeof(val));
    container =
        containerptr_roaring_bitmap_add(r, val, &typecode, &containerindex);
    prev = val;
    i++;
    for (; i < n_args; i++) {
        memcpy(&val, vals + i, sizeof(val));
        if (((prev ^ val) >> 16) ==
            0) {  // no need to seek the container, it is at hand
            // because we already have the container at hand, we can do the
            // insertion
            // automatically, bypassing the roaring_bitmap_add call
            uint8_t newtypecode = typecode;
            container_t *container2 =
                container_add(container, val & 0xFFFF, typecode, &newtypecode);
            if (container2 != container) {  // rare instance when we need to
                                            // change the container type
                container_free(container, typecode);
                ra_set_container_at_index(&r->high_low_container,
                                          containerindex, container2,
                                          newtypecode);
                typecode = newtypecode;
                container = container2;
            }
        } else {
            container = containerptr_roaring_bitmap_add(r, val, &typecode,
                                                        &containerindex);
        }
        prev = val;
    }
}

static roaring_bitmap_t *roaring_bitmap_of_ptr(size_t n_args, const uint32_t *vals) {
    roaring_bitmap_t *answer = roaring_bitmap_create();
    roaring_bitmap_add_many(answer, n_args, vals);
    return answer;
}

static roaring_bitmap_t *roaring_bitmap_of(size_t n_args, ...) {
    // todo: could be greatly optimized but we do not expect this call to ever
    // include long lists
    roaring_bitmap_t *answer = roaring_bitmap_create();
    va_list ap;
    va_start(ap, n_args);
    size_t i; for (i = 1; i <= n_args; i++) {
        uint32_t val = va_arg(ap, uint32_t);
        roaring_bitmap_add(answer, val);
    }
    va_end(ap);
    return answer;
}

static inline uint32_t minimum_uint32(uint32_t a, uint32_t b) {
    return (a < b) ? a : b;
}

static inline uint64_t minimum_uint64(uint64_t a, uint64_t b) {
    return (a < b) ? a : b;
}

static roaring_bitmap_t *roaring_bitmap_from_range(uint64_t min, uint64_t max,
                                            uint32_t step) {
    if(max >= UINT64_C(0x100000000)) {
        max = UINT64_C(0x100000000);
    }
    if (step == 0) return NULL;
    if (max <= min) return NULL;
    roaring_bitmap_t *answer = roaring_bitmap_create();
    if (step >= (1 << 16)) {
        uint32_t value; for (value = (uint32_t)min; value < max; value += step) {
            roaring_bitmap_add(answer, value);
        }
        return answer;
    }
    uint64_t min_tmp = min;
    do {
        uint32_t key = (uint32_t)min_tmp >> 16;
        uint32_t container_min = min_tmp & 0xFFFF;
        uint32_t container_max = (uint32_t)minimum_uint64(max - (key << 16), 1 << 16);
        uint8_t type;
        container_t *container = container_from_range(&type, container_min,
                                               container_max, (uint16_t)step);
        ra_append(&answer->high_low_container, key, container, type);
        uint32_t gap = container_max - container_min + step - 1;
        min_tmp += gap - (gap % step);
    } while (min_tmp < max);
    // cardinality of bitmap will be ((uint64_t) max - min + step - 1 ) / step
    return answer;
}

static void roaring_bitmap_add_range_closed(roaring_bitmap_t *r, uint32_t min, uint32_t max) {
    if (min > max) {
        return;
    }

    roaring_array_t *ra = &r->high_low_container;

    uint32_t min_key = min >> 16;
    uint32_t max_key = max >> 16;

    int32_t num_required_containers = max_key - min_key + 1;
    int32_t suffix_length = count_greater(ra->keys, ra->size, max_key);
    int32_t prefix_length = count_less(ra->keys, ra->size - suffix_length,
                                       min_key);
    int32_t common_length = ra->size - prefix_length - suffix_length;

    if (num_required_containers > common_length) {
        ra_shift_tail(ra, suffix_length,
                      num_required_containers - common_length);
    }

    int32_t src = prefix_length + common_length - 1;
    int32_t dst = ra->size - suffix_length - 1;
    uint32_t key; for ( key = max_key; key != min_key-1; key--) { // beware of min_key==0
        uint32_t container_min = (min_key == key) ? (min & 0xffff) : 0;
        uint32_t container_max = (max_key == key) ? (max & 0xffff) : 0xffff;
        container_t* new_container;
        uint8_t new_type;

        if (src >= 0 && ra->keys[src] == key) {
            ra_unshare_container_at_index(ra, src);
            new_container = container_add_range(ra->containers[src],
                                                ra->typecodes[src],
                                                container_min, container_max,
                                                &new_type);
            if (new_container != ra->containers[src]) {
                container_free(ra->containers[src],
                               ra->typecodes[src]);
            }
            src--;
        } else {
            new_container = container_from_range(&new_type, container_min,
                                                 container_max+1, 1);
        }
        ra_replace_key_and_container_at_index(ra, dst, key, new_container,
                                              new_type);
        dst--;
    }
}

static void roaring_bitmap_remove_range_closed(roaring_bitmap_t *r, uint32_t min, uint32_t max) {
    if (min > max) {
        return;
    }

    roaring_array_t *ra = &r->high_low_container;

    uint32_t min_key = min >> 16;
    uint32_t max_key = max >> 16;

    int32_t src = count_less(ra->keys, ra->size, min_key);
    int32_t dst = src;
    while (src < ra->size && ra->keys[src] <= max_key) {
        uint32_t container_min = (min_key == ra->keys[src]) ? (min & 0xffff) : 0;
        uint32_t container_max = (max_key == ra->keys[src]) ? (max & 0xffff) : 0xffff;
        ra_unshare_container_at_index(ra, src);
        container_t *new_container;
        uint8_t new_type;
        new_container = container_remove_range(ra->containers[src],
                                               ra->typecodes[src],
                                               container_min, container_max,
                                               &new_type);
        if (new_container != ra->containers[src]) {
            container_free(ra->containers[src],
                           ra->typecodes[src]);
        }
        if (new_container) {
            ra_replace_key_and_container_at_index(ra, dst, ra->keys[src],
                                                  new_container, new_type);
            dst++;
        }
        src++;
    }
    if (src > dst) {
        ra_shift_tail(ra, ra->size - src, dst - src);
    }
}

extern inline void roaring_bitmap_add_range(roaring_bitmap_t *r, uint64_t min, uint64_t max);
extern inline void roaring_bitmap_remove_range(roaring_bitmap_t *r, uint64_t min, uint64_t max);

static void roaring_bitmap_printf(const roaring_bitmap_t *r) {
    const roaring_array_t *ra = &r->high_low_container;

    printf("{");
    int i = 0; for (i = 0; i < ra->size; ++i) {
        container_printf_as_uint32_array(ra->containers[i], ra->typecodes[i],
                                         ((uint32_t)ra->keys[i]) << 16);

        if (i + 1 < ra->size) {
            printf(",");
        }
    }
    printf("}");
}

static void roaring_bitmap_printf_describe(const roaring_bitmap_t *r) {
    const roaring_array_t *ra = &r->high_low_container;

    printf("{");
    int i = 0; for (i = 0; i < ra->size; ++i) {
        printf("%d: %s (%d)", ra->keys[i],
               get_full_container_name(ra->containers[i], ra->typecodes[i]),
               container_get_cardinality(ra->containers[i], ra->typecodes[i]));
        if (ra->typecodes[i] == SHARED_CONTAINER_TYPE) {
            printf(
                "(shared count = %" PRIu32 " )",
                    CAST_shared(ra->containers[i])->counter);
        }

        if (i + 1 < ra->size) {
            printf(", ");
        }
    }
    printf("}");
}

typedef struct min_max_sum_s {
    uint32_t min;
    uint32_t max;
    uint64_t sum;
} min_max_sum_t;

static bool min_max_sum_fnc(uint32_t value, void *param) {
    min_max_sum_t *mms = (min_max_sum_t *)param;
    if (value > mms->max) mms->max = value;
    if (value < mms->min) mms->min = value;
    mms->sum += value;
    return true;  // we always process all data points
}

/**
*  (For advanced users.)
* Collect statistics about the bitmap
*/
static void roaring_bitmap_statistics(const roaring_bitmap_t *r,
                               roaring_statistics_t *stat) {
    const roaring_array_t *ra = &r->high_low_container;

    memset(stat, 0, sizeof(*stat));
    stat->n_containers = ra->size;
    stat->cardinality = roaring_bitmap_get_cardinality(r);
    min_max_sum_t mms;
    mms.min = UINT32_C(0xFFFFFFFF);
    mms.max = UINT32_C(0);
    mms.sum = 0;
    roaring_iterate(r, &min_max_sum_fnc, &mms);
    stat->min_value = mms.min;
    stat->max_value = mms.max;
    stat->sum_value = mms.sum;

    int i = 0; for (i = 0; i < ra->size; ++i) {
        uint8_t truetype =
            get_container_type(ra->containers[i], ra->typecodes[i]);
        uint32_t card =
            container_get_cardinality(ra->containers[i], ra->typecodes[i]);
        uint32_t sbytes =
            container_size_in_bytes(ra->containers[i], ra->typecodes[i]);
        switch (truetype) {
            case BITSET_CONTAINER_TYPE:
                stat->n_bitset_containers++;
                stat->n_values_bitset_containers += card;
                stat->n_bytes_bitset_containers += sbytes;
                break;
            case ARRAY_CONTAINER_TYPE:
                stat->n_array_containers++;
                stat->n_values_array_containers += card;
                stat->n_bytes_array_containers += sbytes;
                break;
            case RUN_CONTAINER_TYPE:
                stat->n_run_containers++;
                stat->n_values_run_containers += card;
                stat->n_bytes_run_containers += sbytes;
                break;
            default:
                assert(false);
                __builtin_unreachable();
        }
    }
}

static roaring_bitmap_t *roaring_bitmap_copy(const roaring_bitmap_t *r) {
    roaring_bitmap_t *ans =
        (roaring_bitmap_t *)ndpi_malloc(sizeof(roaring_bitmap_t));
    if (!ans) {
        return NULL;
    }
    if (!ra_init_with_capacity(  // allocation of list of containers can fail
                &ans->high_low_container, r->high_low_container.size)
    ){
        ndpi_free(ans);
        return NULL;
    }
    if (!ra_overwrite(  // memory allocation of individual containers may fail
                &r->high_low_container, &ans->high_low_container, is_cow(r))
    ){
        roaring_bitmap_free(ans);  // overwrite should leave in freeable state
        return NULL;
    }
    roaring_bitmap_set_copy_on_write(ans, is_cow(r));
    return ans;
}

static bool roaring_bitmap_overwrite(roaring_bitmap_t *dest,
                                     const roaring_bitmap_t *src) {
    roaring_bitmap_set_copy_on_write(dest, is_cow(src));
    return ra_overwrite(&src->high_low_container, &dest->high_low_container,
                        is_cow(src));
}

static void roaring_bitmap_free(const roaring_bitmap_t *r) {
    if (!is_frozen(r)) {
      ra_clear((roaring_array_t*)&r->high_low_container);
    }
    ndpi_free((roaring_bitmap_t*)r);
}

static void roaring_bitmap_clear(roaring_bitmap_t *r) {
  ra_reset(&r->high_low_container);
}

static void roaring_bitmap_add(roaring_bitmap_t *r, uint32_t val) {
    roaring_array_t *ra = &r->high_low_container;

    const uint16_t hb = val >> 16;
    const int i = ra_get_index(ra, hb);
    uint8_t typecode;
    if (i >= 0) {
        ra_unshare_container_at_index(ra, i);
        container_t *container =
            ra_get_container_at_index(ra, i, &typecode);
        uint8_t newtypecode = typecode;
        container_t *container2 =
            container_add(container, val & 0xFFFF, typecode, &newtypecode);
        if (container2 != container) {
            container_free(container, typecode);
            ra_set_container_at_index(&r->high_low_container, i, container2,
                                      newtypecode);
        }
    } else {
        array_container_t *newac = array_container_create();
        container_t *container = container_add(newac, val & 0xFFFF,
                                        ARRAY_CONTAINER_TYPE, &typecode);
        // we could just assume that it stays an array container
        ra_insert_new_key_value_at(&r->high_low_container, -i - 1, hb,
                                   container, typecode);
    }
}

static bool roaring_bitmap_add_checked(roaring_bitmap_t *r, uint32_t val) {
    const uint16_t hb = val >> 16;
    const int i = ra_get_index(&r->high_low_container, hb);
    uint8_t typecode;
    bool result = false;
    if (i >= 0) {
        ra_unshare_container_at_index(&r->high_low_container, i);
        container_t *container =
            ra_get_container_at_index(&r->high_low_container, i, &typecode);

        const int oldCardinality =
            container_get_cardinality(container, typecode);

        uint8_t newtypecode = typecode;
        container_t *container2 =
            container_add(container, val & 0xFFFF, typecode, &newtypecode);
        if (container2 != container) {
            container_free(container, typecode);
            ra_set_container_at_index(&r->high_low_container, i, container2,
                                      newtypecode);
            result = true;
        } else {
            const int newCardinality =
                container_get_cardinality(container, newtypecode);

            result = oldCardinality != newCardinality;
        }
    } else {
        array_container_t *newac = array_container_create();
        container_t *container = container_add(newac, val & 0xFFFF,
                                        ARRAY_CONTAINER_TYPE, &typecode);
        // we could just assume that it stays an array container
        ra_insert_new_key_value_at(&r->high_low_container, -i - 1, hb,
                                   container, typecode);
        result = true;
    }

    return result;
}

static void roaring_bitmap_remove(roaring_bitmap_t *r, uint32_t val) {
    const uint16_t hb = val >> 16;
    const int i = ra_get_index(&r->high_low_container, hb);
    uint8_t typecode;
    if (i >= 0) {
        ra_unshare_container_at_index(&r->high_low_container, i);
        container_t *container =
            ra_get_container_at_index(&r->high_low_container, i, &typecode);
        uint8_t newtypecode = typecode;
        container_t *container2 =
            container_remove(container, val & 0xFFFF, typecode, &newtypecode);
        if (container2 != container) {
            container_free(container, typecode);
            ra_set_container_at_index(&r->high_low_container, i, container2,
                                      newtypecode);
        }
        if (container_get_cardinality(container2, newtypecode) != 0) {
            ra_set_container_at_index(&r->high_low_container, i, container2,
                                      newtypecode);
        } else {
            ra_remove_at_index_and_free(&r->high_low_container, i);
        }
    }
}

static bool roaring_bitmap_remove_checked(roaring_bitmap_t *r, uint32_t val) {
    const uint16_t hb = val >> 16;
    const int i = ra_get_index(&r->high_low_container, hb);
    uint8_t typecode;
    bool result = false;
    if (i >= 0) {
        ra_unshare_container_at_index(&r->high_low_container, i);
        container_t *container =
            ra_get_container_at_index(&r->high_low_container, i, &typecode);

        const int oldCardinality =
            container_get_cardinality(container, typecode);

        uint8_t newtypecode = typecode;
        container_t *container2 =
            container_remove(container, val & 0xFFFF, typecode, &newtypecode);
        if (container2 != container) {
            container_free(container, typecode);
            ra_set_container_at_index(&r->high_low_container, i, container2,
                                      newtypecode);
        }

        const int newCardinality =
            container_get_cardinality(container2, newtypecode);

        if (newCardinality != 0) {
            ra_set_container_at_index(&r->high_low_container, i, container2,
                                      newtypecode);
        } else {
            ra_remove_at_index_and_free(&r->high_low_container, i);
        }

        result = oldCardinality != newCardinality;
    }
    return result;
}

static void roaring_bitmap_remove_many(roaring_bitmap_t *r, size_t n_args,
                                const uint32_t *vals) {
    if (n_args == 0 || r->high_low_container.size == 0) {
        return;
    }
    int32_t pos = -1; // position of the container used in the previous iteration
    size_t i; for (i = 0; i < n_args; i++) {
        uint16_t key = (uint16_t)(vals[i] >> 16);
        if (pos < 0 || key != r->high_low_container.keys[pos]) {
            pos = ra_get_index(&r->high_low_container, key);
        }
        if (pos >= 0) {
            uint8_t new_typecode;
            container_t *new_container;
            new_container = container_remove(r->high_low_container.containers[pos],
                                             vals[i] & 0xffff,
                                             r->high_low_container.typecodes[pos],
                                             &new_typecode);
            if (new_container != r->high_low_container.containers[pos]) {
                container_free(r->high_low_container.containers[pos],
                               r->high_low_container.typecodes[pos]);
                ra_replace_key_and_container_at_index(&r->high_low_container,
                                                      pos, key, new_container,
                                                      new_typecode);
            }
            if (!container_nonzero_cardinality(new_container, new_typecode)) {
                container_free(new_container, new_typecode);
                ra_remove_at_index(&r->high_low_container, pos);
                pos = -1;
            }
        }
    }
}

// there should be some SIMD optimizations possible here
static roaring_bitmap_t *roaring_bitmap_and(const roaring_bitmap_t *x1,
                                     const roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    uint32_t neededcap = length1 > length2 ? length2 : length1;
    roaring_bitmap_t *answer = roaring_bitmap_create_with_capacity(neededcap);
    roaring_bitmap_set_copy_on_write(answer, is_cow(x1) || is_cow(x2));

    int pos1 = 0, pos2 = 0;

    while (pos1 < length1 && pos2 < length2) {
        const uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
        const uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        if (s1 == s2) {
            uint8_t type1, type2;
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            container_t *c = container_and(c1, type1, c2, type2, &result_type);

            if (container_nonzero_cardinality(c, result_type)) {
                ra_append(&answer->high_low_container, s1, c, result_type);
            } else {
                container_free(c, result_type);  // otherwise: memory leak!
            }
            ++pos1;
            ++pos2;
        } else if (s1 < s2) {  // s1 < s2
            pos1 = ra_advance_until(&x1->high_low_container, s2, pos1);
        } else {  // s1 > s2
            pos2 = ra_advance_until(&x2->high_low_container, s1, pos2);
        }
    }
    return answer;
}

/**
 * Compute the union of 'number' bitmaps.
 */
static roaring_bitmap_t *roaring_bitmap_or_many(size_t number,
                                         const roaring_bitmap_t **x) {
    if (number == 0) {
        return roaring_bitmap_create();
    }
    if (number == 1) {
        return roaring_bitmap_copy(x[0]);
    }
    roaring_bitmap_t *answer =
        roaring_bitmap_lazy_or(x[0], x[1], LAZY_OR_BITSET_CONVERSION);
    size_t i; for (i = 2; i < number; i++) {
        roaring_bitmap_lazy_or_inplace(answer, x[i], LAZY_OR_BITSET_CONVERSION);
    }
    roaring_bitmap_repair_after_lazy(answer);
    return answer;
}

/**
 * Compute the xor of 'number' bitmaps.
 */
static roaring_bitmap_t *roaring_bitmap_xor_many(size_t number,
                                          const roaring_bitmap_t **x) {
    if (number == 0) {
        return roaring_bitmap_create();
    }
    if (number == 1) {
        return roaring_bitmap_copy(x[0]);
    }
    roaring_bitmap_t *answer = roaring_bitmap_lazy_xor(x[0], x[1]);
    size_t i; for (i = 2; i < number; i++) {
        roaring_bitmap_lazy_xor_inplace(answer, x[i]);
    }
    roaring_bitmap_repair_after_lazy(answer);
    return answer;
}

// inplace and (modifies its first argument).
static void roaring_bitmap_and_inplace(roaring_bitmap_t *x1,
                                const roaring_bitmap_t *x2) {
    if (x1 == x2) return;
    int pos1 = 0, pos2 = 0, intersection_size = 0;
    const int length1 = ra_get_size(&x1->high_low_container);
    const int length2 = ra_get_size(&x2->high_low_container);

    // any skipped-over or newly emptied containers in x1
    // have to be freed.
    while (pos1 < length1 && pos2 < length2) {
        const uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
        const uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        if (s1 == s2) {
            uint8_t type1, type2, result_type;
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);

            // We do the computation "in place" only when c1 is not a shared container.
            // Rationale: using a shared container safely with in place computation would
            // require making a copy and then doing the computation in place which is likely
            // less efficient than avoiding in place entirely and always generating a new
            // container.
            container_t *c =
                (type1 == SHARED_CONTAINER_TYPE)
                    ? container_and(c1, type1, c2, type2, &result_type)
                    : container_iand(c1, type1, c2, type2, &result_type);

            if (c != c1) {  // in this instance a new container was created, and
                            // we need to free the old one
                container_free(c1, type1);
            }
            if (container_nonzero_cardinality(c, result_type)) {
                ra_replace_key_and_container_at_index(&x1->high_low_container,
                                                      intersection_size, s1, c,
                                                      result_type);
                intersection_size++;
            } else {
                container_free(c, result_type);
            }
            ++pos1;
            ++pos2;
        } else if (s1 < s2) {
            pos1 = ra_advance_until_freeing(&x1->high_low_container, s2, pos1);
        } else {  // s1 > s2
            pos2 = ra_advance_until(&x2->high_low_container, s1, pos2);
        }
    }

    // if we ended early because x2 ran out, then all remaining in x1 should be
    // freed
    while (pos1 < length1) {
        container_free(x1->high_low_container.containers[pos1],
                       x1->high_low_container.typecodes[pos1]);
        ++pos1;
    }

    // all containers after this have either been copied or freed
    ra_downsize(&x1->high_low_container, intersection_size);
}

static roaring_bitmap_t *roaring_bitmap_or(const roaring_bitmap_t *x1,
                                    const roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    if (0 == length1) {
        return roaring_bitmap_copy(x2);
    }
    if (0 == length2) {
        return roaring_bitmap_copy(x1);
    }
    roaring_bitmap_t *answer =
        roaring_bitmap_create_with_capacity(length1 + length2);
    roaring_bitmap_set_copy_on_write(answer, is_cow(x1) || is_cow(x2));
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            container_t *c = container_or(c1, type1, c2, type2, &result_type);

            // since we assume that the initial containers are non-empty, the
            // result here
            // can only be non-empty
            ra_append(&answer->high_low_container, s1, c, result_type);
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            // c1 = container_clone(c1, type1);
            c1 = get_copy_of_container(c1, &type1, is_cow(x1));
            if (is_cow(x1)) {
                ra_set_container_at_index(&x1->high_low_container, pos1, c1,
                                          type1);
            }
            ra_append(&answer->high_low_container, s1, c1, type1);
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            // c2 = container_clone(c2, type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }
            ra_append(&answer->high_low_container, s2, c2, type2);
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&answer->high_low_container,
                             &x2->high_low_container, pos2, length2,
                             is_cow(x2));
    } else if (pos2 == length2) {
        ra_append_copy_range(&answer->high_low_container,
                             &x1->high_low_container, pos1, length1,
                             is_cow(x1));
    }
    return answer;
}

// inplace or (modifies its first argument).
static void roaring_bitmap_or_inplace(roaring_bitmap_t *x1,
                               const roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    int length1 = x1->high_low_container.size;
    const int length2 = x2->high_low_container.size;

    if (0 == length2) return;

    if (0 == length1) {
        roaring_bitmap_overwrite(x1, x2);
        return;
    }
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            if (!container_is_full(c1, type1)) {
                container_t *c2 = ra_get_container_at_index(
                                        &x2->high_low_container, pos2, &type2);
                container_t *c =
                    (type1 == SHARED_CONTAINER_TYPE)
                        ? container_or(c1, type1, c2, type2, &result_type)
                        : container_ior(c1, type1, c2, type2, &result_type);

                if (c != c1) {  // in this instance a new container was created,
                                // and we need to free the old one
                    container_free(c1, type1);
                }
                ra_set_container_at_index(&x1->high_low_container, pos1, c,
                                          result_type);
            }
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(&x2->high_low_container,
                                                        pos2, &type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }

            // container_t *c2_clone = container_clone(c2, type2);
            ra_insert_new_key_value_at(&x1->high_low_container, pos1, s2, c2,
                                       type2);
            pos1++;
            length1++;
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&x1->high_low_container, &x2->high_low_container,
                             pos2, length2, is_cow(x2));
    }
}

static roaring_bitmap_t *roaring_bitmap_xor(const roaring_bitmap_t *x1,
                                     const roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    if (0 == length1) {
        return roaring_bitmap_copy(x2);
    }
    if (0 == length2) {
        return roaring_bitmap_copy(x1);
    }
    roaring_bitmap_t *answer =
        roaring_bitmap_create_with_capacity(length1 + length2);
    roaring_bitmap_set_copy_on_write(answer, is_cow(x1) || is_cow(x2));
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            container_t *c = container_xor(c1, type1, c2, type2, &result_type);

            if (container_nonzero_cardinality(c, result_type)) {
                ra_append(&answer->high_low_container, s1, c, result_type);
            } else {
                container_free(c, result_type);
            }
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            container_t *c1 = ra_get_container_at_index(
                                &x1->high_low_container, pos1, &type1);
            c1 = get_copy_of_container(c1, &type1, is_cow(x1));
            if (is_cow(x1)) {
                ra_set_container_at_index(&x1->high_low_container, pos1, c1,
                                          type1);
            }
            ra_append(&answer->high_low_container, s1, c1, type1);
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                &x2->high_low_container, pos2, &type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }
            ra_append(&answer->high_low_container, s2, c2, type2);
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&answer->high_low_container,
                             &x2->high_low_container, pos2, length2,
                             is_cow(x2));
    } else if (pos2 == length2) {
        ra_append_copy_range(&answer->high_low_container,
                             &x1->high_low_container, pos1, length1,
                             is_cow(x1));
    }
    return answer;
}

// inplace xor (modifies its first argument).

static void roaring_bitmap_xor_inplace(roaring_bitmap_t *x1,
                                const roaring_bitmap_t *x2) {
    assert(x1 != x2);
    uint8_t result_type = 0;
    int length1 = x1->high_low_container.size;
    const int length2 = x2->high_low_container.size;

    if (0 == length2) return;

    if (0 == length1) {
        roaring_bitmap_overwrite(x1, x2);
        return;
    }

    // XOR can have new containers inserted from x2, but can also
    // lose containers when x1 and x2 are nonempty and identical.

    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);

            // We do the computation "in place" only when c1 is not a shared container.
            // Rationale: using a shared container safely with in place computation would
            // require making a copy and then doing the computation in place which is likely
            // less efficient than avoiding in place entirely and always generating a new
            // container.

            container_t *c;
            if (type1 == SHARED_CONTAINER_TYPE) {
                c = container_xor(c1, type1, c2, type2, &result_type);
                shared_container_free(CAST_shared(c1));  // so release
            }
            else {
                c = container_ixor(c1, type1, c2, type2, &result_type);
            }

            if (container_nonzero_cardinality(c, result_type)) {
                ra_set_container_at_index(&x1->high_low_container, pos1, c,
                                          result_type);
                ++pos1;
            } else {
                container_free(c, result_type);
                ra_remove_at_index(&x1->high_low_container, pos1);
                --length1;
            }

            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }

            ra_insert_new_key_value_at(&x1->high_low_container, pos1, s2, c2,
                                       type2);
            pos1++;
            length1++;
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&x1->high_low_container, &x2->high_low_container,
                             pos2, length2, is_cow(x2));
    }
}

static roaring_bitmap_t *roaring_bitmap_andnot(const roaring_bitmap_t *x1,
                                        const roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    if (0 == length1) {
        roaring_bitmap_t *empty_bitmap = roaring_bitmap_create();
        roaring_bitmap_set_copy_on_write(empty_bitmap, is_cow(x1) || is_cow(x2));
        return empty_bitmap;
    }
    if (0 == length2) {
        return roaring_bitmap_copy(x1);
    }
    roaring_bitmap_t *answer = roaring_bitmap_create_with_capacity(length1);
    roaring_bitmap_set_copy_on_write(answer, is_cow(x1) || is_cow(x2));

    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = 0;
    uint16_t s2 = 0;
    while (true) {
        s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
        s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            container_t *c = container_andnot(c1, type1, c2, type2,
                                              &result_type);

            if (container_nonzero_cardinality(c, result_type)) {
                ra_append(&answer->high_low_container, s1, c, result_type);
            } else {
                container_free(c, result_type);
            }
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
        } else if (s1 < s2) {  // s1 < s2
            const int next_pos1 =
                ra_advance_until(&x1->high_low_container, s2, pos1);
            ra_append_copy_range(&answer->high_low_container,
                                 &x1->high_low_container, pos1, next_pos1,
                                 is_cow(x1));
            // TODO : perhaps some of the copy_on_write should be based on
            // answer rather than x1 (more stringent?).  Many similar cases
            pos1 = next_pos1;
            if (pos1 == length1) break;
        } else {  // s1 > s2
            pos2 = ra_advance_until(&x2->high_low_container, s1, pos2);
            if (pos2 == length2) break;
        }
    }
    if (pos2 == length2) {
        ra_append_copy_range(&answer->high_low_container,
                             &x1->high_low_container, pos1, length1,
                             is_cow(x1));
    }
    return answer;
}

// inplace andnot (modifies its first argument).

static void roaring_bitmap_andnot_inplace(roaring_bitmap_t *x1,
                                   const roaring_bitmap_t *x2) {
    assert(x1 != x2);

    uint8_t result_type = 0;
    int length1 = x1->high_low_container.size;
    const int length2 = x2->high_low_container.size;
    int intersection_size = 0;

    if (0 == length2) return;

    if (0 == length1) {
        roaring_bitmap_clear(x1);
        return;
    }

    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);

            // We do the computation "in place" only when c1 is not a shared container.
            // Rationale: using a shared container safely with in place computation would
            // require making a copy and then doing the computation in place which is likely
            // less efficient than avoiding in place entirely and always generating a new
            // container.

            container_t *c;
            if (type1 == SHARED_CONTAINER_TYPE) {
                c = container_andnot(c1, type1, c2, type2, &result_type);
                shared_container_free(CAST_shared(c1));  // release
            }
            else {
                c = container_iandnot(c1, type1, c2, type2, &result_type);
            }

            if (container_nonzero_cardinality(c, result_type)) {
                ra_replace_key_and_container_at_index(&x1->high_low_container,
                                                      intersection_size++, s1,
                                                      c, result_type);
            } else {
                container_free(c, result_type);
            }

            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            if (pos1 != intersection_size) {
                container_t *c1 = ra_get_container_at_index(
                                        &x1->high_low_container, pos1, &type1);

                ra_replace_key_and_container_at_index(&x1->high_low_container,
                                                      intersection_size, s1, c1,
                                                      type1);
            }
            intersection_size++;
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            pos2 = ra_advance_until(&x2->high_low_container, s1, pos2);
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }

    if (pos1 < length1) {
        // all containers between intersection_size and
        // pos1 are junk.  However, they have either been moved
        // (thus still referenced) or involved in an iandnot
        // that will clean up all containers that could not be reused.
        // Thus we should not free the junk containers between
        // intersection_size and pos1.
        if (pos1 > intersection_size) {
            // left slide of remaining items
            ra_copy_range(&x1->high_low_container, pos1, length1,
                          intersection_size);
        }
        // else current placement is fine
        intersection_size += (length1 - pos1);
    }
    ra_downsize(&x1->high_low_container, intersection_size);
}

static uint64_t roaring_bitmap_get_cardinality(const roaring_bitmap_t *r) {
    const roaring_array_t *ra = &r->high_low_container;

    uint64_t card = 0;
    int i = 0; for (i = 0; i < ra->size; ++i)
        card += container_get_cardinality(ra->containers[i], ra->typecodes[i]);
    return card;
}

static uint64_t roaring_bitmap_range_cardinality(const roaring_bitmap_t *r,
                                          uint64_t range_start,
                                          uint64_t range_end) {
    const roaring_array_t *ra = &r->high_low_container;

    if (range_end > UINT32_MAX) {
        range_end = UINT32_MAX + UINT64_C(1);
    }
    if (range_start >= range_end) {
        return 0;
    }
    range_end--; // make range_end inclusive
    // now we have: 0 <= range_start <= range_end <= UINT32_MAX

    uint16_t minhb = range_start >> 16;
    uint16_t maxhb = range_end >> 16;

    uint64_t card = 0;

    int i = ra_get_index(ra, minhb);
    if (i >= 0) {
        if (minhb == maxhb) {
            card += container_rank(ra->containers[i], ra->typecodes[i],
                                   range_end & 0xffff);
        } else {
            card += container_get_cardinality(ra->containers[i],
                                              ra->typecodes[i]);
        }
        if ((range_start & 0xffff) != 0) {
            card -= container_rank(ra->containers[i], ra->typecodes[i],
                                   (range_start & 0xffff) - 1);
        }
        i++;
    } else {
        i = -i - 1;
    }

    for (; i < ra->size; i++) {
        uint16_t key = ra->keys[i];
        if (key < maxhb) {
            card += container_get_cardinality(ra->containers[i],
                                              ra->typecodes[i]);
        } else if (key == maxhb) {
            card += container_rank(ra->containers[i], ra->typecodes[i],
                                   range_end & 0xffff);
            break;
        } else {
            break;
        }
    }

    return card;
}


static bool roaring_bitmap_is_empty(const roaring_bitmap_t *r) {
    return r->high_low_container.size == 0;
}

static void roaring_bitmap_to_uint32_array(const roaring_bitmap_t *r, uint32_t *ans) {
    ra_to_uint32_array(&r->high_low_container, ans);
}

static bool roaring_bitmap_range_uint32_array(const roaring_bitmap_t *r,
                                       size_t offset, size_t limit,
                                       uint32_t *ans) {
    return ra_range_uint32_array(&r->high_low_container, offset, limit, ans);
}

/** convert array and bitmap containers to run containers when it is more
 * efficient;
 * also convert from run containers when more space efficient.  Returns
 * true if the result has at least one run container.
*/
static bool roaring_bitmap_run_optimize(roaring_bitmap_t *r) {
    bool answer = false;
    int i = 0; for (i = 0; i < r->high_low_container.size; i++) {
        uint8_t type_original, type_after;
        ra_unshare_container_at_index(
            &r->high_low_container, i);  // TODO: this introduces extra cloning!
        container_t *c = ra_get_container_at_index(&r->high_low_container, i,
                                                   &type_original);
        container_t *c1 = convert_run_optimize(c, type_original, &type_after);
        if (type_after == RUN_CONTAINER_TYPE) {
            answer = true;
        }
        ra_set_container_at_index(&r->high_low_container, i, c1, type_after);
    }
    return answer;
}

static size_t roaring_bitmap_shrink_to_fit(roaring_bitmap_t *r) {
    size_t answer = 0;
    int i = 0; for (i = 0; i < r->high_low_container.size; i++) {
        uint8_t type_original;
        container_t *c = ra_get_container_at_index(&r->high_low_container, i,
                                                   &type_original);
        answer += container_shrink_to_fit(c, type_original);
    }
    answer += ra_shrink_to_fit(&r->high_low_container);
    return answer;
}

/**
 *  Remove run-length encoding even when it is more space efficient
 *  return whether a change was applied
 */
static bool roaring_bitmap_remove_run_compression(roaring_bitmap_t *r) {
    bool answer = false;
    int i = 0; for (i = 0; i < r->high_low_container.size; i++) {
        uint8_t type_original, type_after;
        container_t *c = ra_get_container_at_index(&r->high_low_container, i,
                                                   &type_original);
        if (get_container_type(c, type_original) == RUN_CONTAINER_TYPE) {
            answer = true;
            if (type_original == SHARED_CONTAINER_TYPE) {
                run_container_t *truec = CAST_run(CAST_shared(c)->container);
                int32_t card = run_container_cardinality(truec);
                container_t *c1 = convert_to_bitset_or_array_container(
                                        truec, card, &type_after);
                shared_container_free(CAST_shared(c));  // frees run as needed
                ra_set_container_at_index(&r->high_low_container, i, c1,
                                          type_after);

            } else {
                int32_t card = run_container_cardinality(CAST_run(c));
                container_t *c1 = convert_to_bitset_or_array_container(
                                    CAST_run(c), card, &type_after);
                run_container_free(CAST_run(c));
                ra_set_container_at_index(&r->high_low_container, i, c1,
                                          type_after);
            }
        }
    }
    return answer;
}

static size_t roaring_bitmap_serialize(const roaring_bitmap_t *r, char *buf) {
    size_t portablesize = roaring_bitmap_portable_size_in_bytes(r);
    uint64_t cardinality = roaring_bitmap_get_cardinality(r);
    uint64_t sizeasarray = cardinality * sizeof(uint32_t) + sizeof(uint32_t);
    if (portablesize < sizeasarray) {
        buf[0] = SERIALIZATION_CONTAINER;
        return roaring_bitmap_portable_serialize(r, buf + 1) + 1;
    } else {
        buf[0] = SERIALIZATION_ARRAY_UINT32;
        memcpy(buf + 1, &cardinality, sizeof(uint32_t));
        roaring_bitmap_to_uint32_array(
            r, (uint32_t *)(buf + 1 + sizeof(uint32_t)));
        return 1 + (size_t)sizeasarray;
    }
}

static size_t roaring_bitmap_size_in_bytes(const roaring_bitmap_t *r) {
    size_t portablesize = roaring_bitmap_portable_size_in_bytes(r);
    uint64_t sizeasarray = roaring_bitmap_get_cardinality(r) * sizeof(uint32_t) +
                         sizeof(uint32_t);
    return portablesize < sizeasarray ? portablesize + 1 : (size_t)sizeasarray + 1;
}

static size_t roaring_bitmap_portable_size_in_bytes(const roaring_bitmap_t *r) {
    return ra_portable_size_in_bytes(&r->high_low_container);
}


static roaring_bitmap_t *roaring_bitmap_portable_deserialize_safe(const char *buf, size_t maxbytes) {
    roaring_bitmap_t *ans =
        (roaring_bitmap_t *)ndpi_malloc(sizeof(roaring_bitmap_t));
    if (ans == NULL) {
        return NULL;
    }
    size_t bytesread;
    bool is_ok = ra_portable_deserialize(&ans->high_low_container, buf, maxbytes, &bytesread);
    if(is_ok) assert(bytesread <= maxbytes);
    roaring_bitmap_set_copy_on_write(ans, false);
    if (!is_ok) {
        ndpi_free(ans);
        return NULL;
    }
    return ans;
}

static roaring_bitmap_t *roaring_bitmap_portable_deserialize(const char *buf) {
    return roaring_bitmap_portable_deserialize_safe(buf, SIZE_MAX);
}


static size_t roaring_bitmap_portable_deserialize_size(const char *buf, size_t maxbytes) {
  return ra_portable_deserialize_size(buf, maxbytes);
}


static size_t roaring_bitmap_portable_serialize(const roaring_bitmap_t *r,
                                         char *buf) {
    return ra_portable_serialize(&r->high_low_container, buf);
}

static roaring_bitmap_t *roaring_bitmap_deserialize(const void *buf) {
    const char *bufaschar = (const char *)buf;
    if (*(const unsigned char *)buf == SERIALIZATION_ARRAY_UINT32) {
        /* This looks like a compressed set of uint32_t elements */
        uint32_t card;
        memcpy(&card, bufaschar + 1, sizeof(uint32_t));
        const uint32_t *elems =
            (const uint32_t *)(bufaschar + 1 + sizeof(uint32_t));

        return roaring_bitmap_of_ptr(card, elems);
    } else if (bufaschar[0] == SERIALIZATION_CONTAINER) {
        return roaring_bitmap_portable_deserialize(bufaschar + 1);
    } else
        return (NULL);
}

static bool roaring_iterate(const roaring_bitmap_t *r, roaring_iterator iterator,
                     void *ptr) {
    const roaring_array_t *ra = &r->high_low_container;

    int i = 0; for (i = 0; i < ra->size; ++i)
        if (!container_iterate(ra->containers[i], ra->typecodes[i],
                               ((uint32_t)ra->keys[i]) << 16,
                               iterator, ptr)) {
            return false;
        }
    return true;
}

static bool roaring_iterate64(const roaring_bitmap_t *r, roaring_iterator64 iterator,
                       uint64_t high_bits, void *ptr) {
    const roaring_array_t *ra = &r->high_low_container;

    int i = 0; for (i = 0; i < ra->size; ++i)
        if (!container_iterate64(
                ra->containers[i], ra->typecodes[i],
                ((uint32_t)ra->keys[i]) << 16, iterator,
                high_bits, ptr)) {
            return false;
        }
    return true;
}

/****
* begin roaring_uint32_iterator_t
*****/

// Partially initializes the roaring iterator when it begins looking at
// a new container.
static bool iter_new_container_partial_init(roaring_uint32_iterator_t *newit) {
    newit->in_container_index = 0;
    newit->run_index = 0;
    newit->current_value = 0;
    if (newit->container_index >= newit->parent->high_low_container.size ||
        newit->container_index < 0) {
        newit->current_value = UINT32_MAX;
        return (newit->has_value = false);
    }
    // assume not empty
    newit->has_value = true;
    // we precompute container, typecode and highbits so that successive
    // iterators do not have to grab them from odd memory locations
    // and have to worry about the (easily predicted) container_unwrap_shared
    // call.
    newit->container =
            newit->parent->high_low_container.containers[newit->container_index];
    newit->typecode =
            newit->parent->high_low_container.typecodes[newit->container_index];
    newit->highbits =
            ((uint32_t)
                    newit->parent->high_low_container.keys[newit->container_index])
                    << 16;
    newit->container =
            container_unwrap_shared(newit->container, &(newit->typecode));
    return newit->has_value;
}

static bool loadfirstvalue(roaring_uint32_iterator_t *newit) {
    if (!iter_new_container_partial_init(newit))
        return newit->has_value;

    switch (newit->typecode) {
        case BITSET_CONTAINER_TYPE: {
            const bitset_container_t *bc = const_CAST_bitset(newit->container);

            uint32_t wordindex = 0;
            uint64_t word;
            while ((word = bc->words[wordindex]) == 0) {
                wordindex++;  // advance
            }
            // here "word" is non-zero
            newit->in_container_index = wordindex * 64 + __builtin_ctzll(word);
            newit->current_value = newit->highbits | newit->in_container_index;
            break; }

        case ARRAY_CONTAINER_TYPE: {
            const array_container_t *ac = const_CAST_array(newit->container);
            newit->current_value = newit->highbits | ac->array[0];
            break; }

        case RUN_CONTAINER_TYPE: {
            const run_container_t *rc = const_CAST_run(newit->container);
            newit->current_value = newit->highbits | rc->runs[0].value;
            break; }

        default:
            // if this ever happens, bug!
            assert(false);
    }  // switch (typecode)
    return true;
}

static bool loadlastvalue(roaring_uint32_iterator_t* newit) {
    if (!iter_new_container_partial_init(newit))
        return newit->has_value;

    switch(newit->typecode) {
        case BITSET_CONTAINER_TYPE: {
            uint32_t wordindex = BITSET_CONTAINER_SIZE_IN_WORDS - 1;
            uint64_t word;
            const bitset_container_t* bitset_container = (const bitset_container_t*)newit->container;
            while ((word = bitset_container->words[wordindex]) == 0)
                --wordindex;

            int num_leading_zeros = __builtin_clzll(word);
            newit->in_container_index = (wordindex * 64) + (63 - num_leading_zeros);
            newit->current_value = newit->highbits | newit->in_container_index;
            break;
        }
        case ARRAY_CONTAINER_TYPE: {
            const array_container_t* array_container = (const array_container_t*)newit->container;
            newit->in_container_index = array_container->cardinality - 1;
            newit->current_value = newit->highbits | array_container->array[newit->in_container_index];
            break;
        }
        case RUN_CONTAINER_TYPE: {
            const run_container_t* run_container = (const run_container_t*)newit->container;
            newit->run_index = run_container->n_runs - 1;
            const rle16_t* last_run = &run_container->runs[newit->run_index];
            newit->current_value = newit->highbits | (last_run->value + last_run->length);
            break;
        }
        default:
            // if this ever happens, bug!
            assert(false);
    }
    return true;
}

// prerequesite: the value should be in range of the container
static bool loadfirstvalue_largeorequal(roaring_uint32_iterator_t *newit, uint32_t val) {
    // Don't have to check return value because of prerequisite
    iter_new_container_partial_init(newit);
    uint16_t lb = val & 0xFFFF;

    switch (newit->typecode) {
        case BITSET_CONTAINER_TYPE: {
            const bitset_container_t *bc = const_CAST_bitset(newit->container);
            newit->in_container_index =
                        bitset_container_index_equalorlarger(bc, lb);
            newit->current_value = newit->highbits | newit->in_container_index;
            break; }

        case ARRAY_CONTAINER_TYPE: {
            const array_container_t *ac = const_CAST_array(newit->container);
            newit->in_container_index =
                        array_container_index_equalorlarger(ac, lb);
            newit->current_value =
                        newit->highbits | ac->array[newit->in_container_index];
            break; }

        case RUN_CONTAINER_TYPE: {
            const run_container_t *rc = const_CAST_run(newit->container);
            newit->run_index = run_container_index_equalorlarger(rc, lb);
            if (rc->runs[newit->run_index].value <= lb) {
                newit->current_value = val;
            } else {
                newit->current_value =
                        newit->highbits | rc->runs[newit->run_index].value;
            }
            break; }

        default:
            __builtin_unreachable();
    }

    return true;
}

static void roaring_init_iterator(const roaring_bitmap_t *r,
                           roaring_uint32_iterator_t *newit) {
    newit->parent = r;
    newit->container_index = 0;
    newit->has_value = loadfirstvalue(newit);
}

static void roaring_init_iterator_last(const roaring_bitmap_t *r,
                                roaring_uint32_iterator_t *newit) {
    newit->parent = r;
    newit->container_index = newit->parent->high_low_container.size - 1;
    newit->has_value = loadlastvalue(newit);
}

static roaring_uint32_iterator_t *roaring_create_iterator(const roaring_bitmap_t *r) {
    roaring_uint32_iterator_t *newit =
        (roaring_uint32_iterator_t *)ndpi_malloc(sizeof(roaring_uint32_iterator_t));
    if (newit == NULL) return NULL;
    roaring_init_iterator(r, newit);
    return newit;
}

static roaring_uint32_iterator_t *roaring_copy_uint32_iterator(
    const roaring_uint32_iterator_t *it) {
    roaring_uint32_iterator_t *newit =
        (roaring_uint32_iterator_t *)ndpi_malloc(sizeof(roaring_uint32_iterator_t));
    memcpy(newit, it, sizeof(roaring_uint32_iterator_t));
    return newit;
}

static bool roaring_move_uint32_iterator_equalorlarger(roaring_uint32_iterator_t *it, uint32_t val) {
    uint16_t hb = val >> 16;
    const int i = ra_get_index(& it->parent->high_low_container, hb);
    if (i >= 0) {
      uint32_t lowvalue = container_maximum(it->parent->high_low_container.containers[i], it->parent->high_low_container.typecodes[i]);
      uint16_t lb = val & 0xFFFF;
      if(lowvalue < lb ) {
        it->container_index = i+1; // will have to load first value of next container
      } else {// the value is necessarily within the range of the container
        it->container_index = i;
        it->has_value = loadfirstvalue_largeorequal(it, val);
        return it->has_value;
      }
    } else {
      // there is no matching, so we are going for the next container
      it->container_index = -i-1;
    }
    it->has_value = loadfirstvalue(it);
    return it->has_value;
}


static bool roaring_advance_uint32_iterator(roaring_uint32_iterator_t *it) {
    if (it->container_index >= it->parent->high_low_container.size) {
        return (it->has_value = false);
    }
    if (it->container_index < 0) {
        it->container_index = 0;
        return (it->has_value = loadfirstvalue(it));
    }

    switch (it->typecode) {
        case BITSET_CONTAINER_TYPE: {
            const bitset_container_t *bc = const_CAST_bitset(it->container);
            it->in_container_index++;

            uint32_t wordindex = it->in_container_index / 64;
            if (wordindex >= BITSET_CONTAINER_SIZE_IN_WORDS) break;

            uint64_t word = bc->words[wordindex] &
                   (UINT64_MAX << (it->in_container_index % 64));
            // next part could be optimized/simplified
            while ((word == 0) &&
                   (wordindex + 1 < BITSET_CONTAINER_SIZE_IN_WORDS)) {
                wordindex++;
                word = bc->words[wordindex];
            }
            if (word != 0) {
                it->in_container_index = wordindex * 64 + __builtin_ctzll(word);
                it->current_value = it->highbits | it->in_container_index;
                return (it->has_value = true);
            }
            break; }

        case ARRAY_CONTAINER_TYPE: {
            const array_container_t *ac = const_CAST_array(it->container);
            it->in_container_index++;
            if (it->in_container_index < ac->cardinality) {
                it->current_value =
                        it->highbits | ac->array[it->in_container_index];
                return (it->has_value = true);
            }
            break; }

        case RUN_CONTAINER_TYPE: {
            if(it->current_value == UINT32_MAX) {  // avoid overflow to zero
                return (it->has_value = false);
            }

            const run_container_t* rc = const_CAST_run(it->container);
            uint32_t limit = (it->highbits | (rc->runs[it->run_index].value +
                                              rc->runs[it->run_index].length));
            if (++it->current_value <= limit) {
                return (it->has_value = true);
            }

            if (++it->run_index < rc->n_runs) {  // Assume the run has a value
                it->current_value =
                        it->highbits | rc->runs[it->run_index].value;
                return (it->has_value = true);
            }
            break;
        }

        default:
            __builtin_unreachable();
    }

    // moving to next container
    it->container_index++;
    return (it->has_value = loadfirstvalue(it));
}

static bool roaring_previous_uint32_iterator(roaring_uint32_iterator_t *it) {
    if (it->container_index < 0) {
        return (it->has_value = false);
    }
    if (it->container_index >= it->parent->high_low_container.size) {
        it->container_index = it->parent->high_low_container.size - 1;
        return (it->has_value = loadlastvalue(it));
    }

    switch (it->typecode) {
        case BITSET_CONTAINER_TYPE: {
            if (--it->in_container_index < 0)
                break;

            const bitset_container_t* bitset_container = (const bitset_container_t*)it->container;
            int32_t wordindex = it->in_container_index / 64;
            uint64_t word = bitset_container->words[wordindex] & (UINT64_MAX >> (63 - (it->in_container_index % 64)));

            while (word == 0 && --wordindex >= 0) {
                word = bitset_container->words[wordindex];
            }
            if (word == 0)
                break;

            int num_leading_zeros = __builtin_clzll(word);
            it->in_container_index = (wordindex * 64) + (63 - num_leading_zeros);
            it->current_value = it->highbits | it->in_container_index;
            return (it->has_value = true);
        }
        case ARRAY_CONTAINER_TYPE: {
            if (--it->in_container_index < 0)
                break;

            const array_container_t* array_container = (const array_container_t*)it->container;
            it->current_value = it->highbits | array_container->array[it->in_container_index];
            return (it->has_value = true);
        }
        case RUN_CONTAINER_TYPE: {
            if(it->current_value == 0)
                return (it->has_value = false);

            const run_container_t* run_container = (const run_container_t*)it->container;
            if (--it->current_value >= (it->highbits | run_container->runs[it->run_index].value)) {
                return (it->has_value = true);
            }

            if (--it->run_index < 0)
                break;

            it->current_value = it->highbits | (run_container->runs[it->run_index].value +
                                                run_container->runs[it->run_index].length);
            return (it->has_value = true);
        }
        default:
            // if this ever happens, bug!
            assert(false);
    }  // switch (typecode)

    // moving to previous container
    it->container_index--;
    return (it->has_value = loadlastvalue(it));
}

static uint32_t roaring_read_uint32_iterator(roaring_uint32_iterator_t *it, uint32_t* buf, uint32_t count) {
  uint32_t ret = 0;
  uint32_t num_values;
  uint32_t wordindex;  // used for bitsets
  uint64_t word;       // used for bitsets
  const array_container_t* acont; //TODO remove
  const run_container_t* rcont; //TODO remove
  const bitset_container_t* bcont; //TODO remove

  while (it->has_value && ret < count) {
    switch (it->typecode) {
      case BITSET_CONTAINER_TYPE:
        bcont = const_CAST_bitset(it->container);
        wordindex = it->in_container_index / 64;
        word = bcont->words[wordindex] & (UINT64_MAX << (it->in_container_index % 64));
        do {
          while (word != 0 && ret < count) {
            buf[0] = it->highbits | (wordindex * 64 + __builtin_ctzll(word));
            word = word & (word - 1);
            buf++;
            ret++;
          }
          while (word == 0 && wordindex+1 < BITSET_CONTAINER_SIZE_IN_WORDS) {
            wordindex++;
            word = bcont->words[wordindex];
          }
        } while (word != 0 && ret < count);
        it->has_value = (word != 0);
        if (it->has_value) {
          it->in_container_index = wordindex * 64 + __builtin_ctzll(word);
          it->current_value = it->highbits | it->in_container_index;
        }
        break;
      case ARRAY_CONTAINER_TYPE:
        acont = const_CAST_array(it->container);
        num_values = minimum_uint32(acont->cardinality - it->in_container_index, count - ret);
        uint32_t i; for (i = 0; i < num_values; i++) {
          buf[i] = it->highbits | acont->array[it->in_container_index + i];
        }
        buf += num_values;
        ret += num_values;
        it->in_container_index += num_values;
        it->has_value = (it->in_container_index < acont->cardinality);
        if (it->has_value) {
          it->current_value = it->highbits | acont->array[it->in_container_index];
        }
        break;
      case RUN_CONTAINER_TYPE:
        rcont = const_CAST_run(it->container);
        //"in_run_index" name is misleading, read it as "max_value_in_current_run"
        do {
          uint32_t largest_run_value = it->highbits | (rcont->runs[it->run_index].value + rcont->runs[it->run_index].length);
          num_values = minimum_uint32(largest_run_value - it->current_value + 1, count - ret);
          uint32_t i; for (i = 0; i < num_values; i++) {
            buf[i] = it->current_value + i;
          }
          it->current_value += num_values; // this can overflow to zero: UINT32_MAX+1=0
          buf += num_values;
          ret += num_values;

          if (it->current_value > largest_run_value || it->current_value == 0) {
            it->run_index++;
            if (it->run_index < rcont->n_runs) {
              it->current_value = it->highbits | rcont->runs[it->run_index].value;
            } else {
              it->has_value = false;
            }
          }
        } while ((ret < count) && it->has_value);
        break;
      default:
        assert(false);
    }
    if (it->has_value) {
      assert(ret == count);
      return ret;
    }
    it->container_index++;
    it->has_value = loadfirstvalue(it);
  }
  return ret;
}



static void roaring_free_uint32_iterator(roaring_uint32_iterator_t *it) { ndpi_free(it); }

/****
* end of roaring_uint32_iterator_t
*****/

static bool roaring_bitmap_equals(const roaring_bitmap_t *r1,
                           const roaring_bitmap_t *r2) {
    const roaring_array_t *ra1 = &r1->high_low_container;
    const roaring_array_t *ra2 = &r2->high_low_container;

    if (ra1->size != ra2->size) {
        return false;
    }
    int i = 0; for (i = 0; i < ra1->size; ++i) {
        if (ra1->keys[i] != ra2->keys[i]) {
            return false;
        }
    }
    for (i = 0; i < ra1->size; ++i) {
        bool areequal = container_equals(ra1->containers[i],
                                         ra1->typecodes[i],
                                         ra2->containers[i],
                                         ra2->typecodes[i]);
        if (!areequal) {
            return false;
        }
    }
    return true;
}

static bool roaring_bitmap_is_subset(const roaring_bitmap_t *r1,
                              const roaring_bitmap_t *r2) {
    const roaring_array_t *ra1 = &r1->high_low_container;
    const roaring_array_t *ra2 = &r2->high_low_container;

    const int length1 = ra1->size,
              length2 = ra2->size;

    int pos1 = 0, pos2 = 0;

    while (pos1 < length1 && pos2 < length2) {
        const uint16_t s1 = ra_get_key_at_index(ra1, pos1);
        const uint16_t s2 = ra_get_key_at_index(ra2, pos2);

        if (s1 == s2) {
            uint8_t type1, type2;
            container_t *c1 = ra_get_container_at_index(ra1, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(ra2, pos2, &type2);
            if (!container_is_subset(c1, type1, c2, type2))
                return false;
            ++pos1;
            ++pos2;
        } else if (s1 < s2) {  // s1 < s2
            return false;
        } else {  // s1 > s2
            pos2 = ra_advance_until(ra2, s1, pos2);
        }
    }
    if (pos1 == length1)
        return true;
    else
        return false;
}

static void insert_flipped_container(roaring_array_t *ans_arr,
                                     const roaring_array_t *x1_arr, uint16_t hb,
                                     uint16_t lb_start, uint16_t lb_end) {
    const int i = ra_get_index(x1_arr, hb);
    const int j = ra_get_index(ans_arr, hb);
    uint8_t ctype_in, ctype_out;
    container_t *flipped_container = NULL;
    if (i >= 0) {
        container_t *container_to_flip =
            ra_get_container_at_index(x1_arr, i, &ctype_in);
        flipped_container =
            container_not_range(container_to_flip, ctype_in, (uint32_t)lb_start,
                                (uint32_t)(lb_end + 1), &ctype_out);

        if (container_get_cardinality(flipped_container, ctype_out))
            ra_insert_new_key_value_at(ans_arr, -j - 1, hb, flipped_container,
                                       ctype_out);
        else {
            container_free(flipped_container, ctype_out);
        }
    } else {
        flipped_container = container_range_of_ones(
            (uint32_t)lb_start, (uint32_t)(lb_end + 1), &ctype_out);
        ra_insert_new_key_value_at(ans_arr, -j - 1, hb, flipped_container,
                                   ctype_out);
    }
}

static void inplace_flip_container(roaring_array_t *x1_arr, uint16_t hb,
                                   uint16_t lb_start, uint16_t lb_end) {
    const int i = ra_get_index(x1_arr, hb);
    uint8_t ctype_in, ctype_out;
    container_t *flipped_container = NULL;
    if (i >= 0) {
        container_t *container_to_flip =
            ra_get_container_at_index(x1_arr, i, &ctype_in);
        flipped_container = container_inot_range(
            container_to_flip, ctype_in, (uint32_t)lb_start,
            (uint32_t)(lb_end + 1), &ctype_out);
        // if a new container was created, the old one was already freed
        if (container_get_cardinality(flipped_container, ctype_out)) {
            ra_set_container_at_index(x1_arr, i, flipped_container, ctype_out);
        } else {
            container_free(flipped_container, ctype_out);
            ra_remove_at_index(x1_arr, i);
        }

    } else {
        flipped_container = container_range_of_ones(
            (uint32_t)lb_start, (uint32_t)(lb_end + 1), &ctype_out);
        ra_insert_new_key_value_at(x1_arr, -i - 1, hb, flipped_container,
                                   ctype_out);
    }
}

static void insert_fully_flipped_container(roaring_array_t *ans_arr,
                                           const roaring_array_t *x1_arr,
                                           uint16_t hb) {
    const int i = ra_get_index(x1_arr, hb);
    const int j = ra_get_index(ans_arr, hb);
    uint8_t ctype_in, ctype_out;
    container_t *flipped_container = NULL;
    if (i >= 0) {
        container_t *container_to_flip =
            ra_get_container_at_index(x1_arr, i, &ctype_in);
        flipped_container =
            container_not(container_to_flip, ctype_in, &ctype_out);
        if (container_get_cardinality(flipped_container, ctype_out))
            ra_insert_new_key_value_at(ans_arr, -j - 1, hb, flipped_container,
                                       ctype_out);
        else {
            container_free(flipped_container, ctype_out);
        }
    } else {
        flipped_container = container_range_of_ones(0U, 0x10000U, &ctype_out);
        ra_insert_new_key_value_at(ans_arr, -j - 1, hb, flipped_container,
                                   ctype_out);
    }
}

static void inplace_fully_flip_container(roaring_array_t *x1_arr, uint16_t hb) {
    const int i = ra_get_index(x1_arr, hb);
    uint8_t ctype_in, ctype_out;
    container_t *flipped_container = NULL;
    if (i >= 0) {
        container_t *container_to_flip =
            ra_get_container_at_index(x1_arr, i, &ctype_in);
        flipped_container =
            container_inot(container_to_flip, ctype_in, &ctype_out);

        if (container_get_cardinality(flipped_container, ctype_out)) {
            ra_set_container_at_index(x1_arr, i, flipped_container, ctype_out);
        } else {
            container_free(flipped_container, ctype_out);
            ra_remove_at_index(x1_arr, i);
        }

    } else {
        flipped_container = container_range_of_ones(0U, 0x10000U, &ctype_out);
        ra_insert_new_key_value_at(x1_arr, -i - 1, hb, flipped_container,
                                   ctype_out);
    }
}

static roaring_bitmap_t *roaring_bitmap_flip(const roaring_bitmap_t *x1,
                                      uint64_t range_start,
                                      uint64_t range_end) {
    if (range_start >= range_end) {
        return roaring_bitmap_copy(x1);
    }
    if(range_end >= UINT64_C(0x100000000)) {
        range_end = UINT64_C(0x100000000);
    }

    roaring_bitmap_t *ans = roaring_bitmap_create();
    roaring_bitmap_set_copy_on_write(ans, is_cow(x1));

    uint16_t hb_start = (uint16_t)(range_start >> 16);
    const uint16_t lb_start = (uint16_t)range_start;  // & 0xFFFF;
    uint16_t hb_end = (uint16_t)((range_end - 1) >> 16);
    const uint16_t lb_end = (uint16_t)(range_end - 1);  // & 0xFFFF;

    ra_append_copies_until(&ans->high_low_container, &x1->high_low_container,
                           hb_start, is_cow(x1));
    if (hb_start == hb_end) {
        insert_flipped_container(&ans->high_low_container,
                                 &x1->high_low_container, hb_start, lb_start,
                                 lb_end);
    } else {
        // start and end containers are distinct
        if (lb_start > 0) {
            // handle first (partial) container
            insert_flipped_container(&ans->high_low_container,
                                     &x1->high_low_container, hb_start,
                                     lb_start, 0xFFFF);
            ++hb_start;  // for the full containers.  Can't wrap.
        }

        if (lb_end != 0xFFFF) --hb_end;  // later we'll handle the partial block

        uint32_t hb; for (hb = hb_start; hb <= hb_end; ++hb) {
            insert_fully_flipped_container(&ans->high_low_container,
                                           &x1->high_low_container, hb);
        }

        // handle a partial final container
        if (lb_end != 0xFFFF) {
            insert_flipped_container(&ans->high_low_container,
                                     &x1->high_low_container, hb_end + 1, 0,
                                     lb_end);
            ++hb_end;
        }
    }
    ra_append_copies_after(&ans->high_low_container, &x1->high_low_container,
                           hb_end, is_cow(x1));
    return ans;
}

static void roaring_bitmap_flip_inplace(roaring_bitmap_t *x1, uint64_t range_start,
                                 uint64_t range_end) {
    if (range_start >= range_end) {
        return;  // empty range
    }
    if(range_end >= UINT64_C(0x100000000)) {
        range_end = UINT64_C(0x100000000);
    }

    uint16_t hb_start = (uint16_t)(range_start >> 16);
    const uint16_t lb_start = (uint16_t)range_start;
    uint16_t hb_end = (uint16_t)((range_end - 1) >> 16);
    const uint16_t lb_end = (uint16_t)(range_end - 1);

    if (hb_start == hb_end) {
        inplace_flip_container(&x1->high_low_container, hb_start, lb_start,
                               lb_end);
    } else {
        // start and end containers are distinct
        if (lb_start > 0) {
            // handle first (partial) container
            inplace_flip_container(&x1->high_low_container, hb_start, lb_start,
                                   0xFFFF);
            ++hb_start;  // for the full containers.  Can't wrap.
        }

        if (lb_end != 0xFFFF) --hb_end;

        uint32_t hb; for (hb = hb_start; hb <= hb_end; ++hb) {
            inplace_fully_flip_container(&x1->high_low_container, hb);
        }
        // handle a partial final container
        if (lb_end != 0xFFFF) {
            inplace_flip_container(&x1->high_low_container, hb_end + 1, 0,
                                   lb_end);
            ++hb_end;
        }
    }
}

static roaring_bitmap_t *roaring_bitmap_lazy_or(const roaring_bitmap_t *x1,
                                         const roaring_bitmap_t *x2,
                                         const bool bitsetconversion) {
    uint8_t result_type = 0;
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    if (0 == length1) {
        return roaring_bitmap_copy(x2);
    }
    if (0 == length2) {
        return roaring_bitmap_copy(x1);
    }
    roaring_bitmap_t *answer =
        roaring_bitmap_create_with_capacity(length1 + length2);
    roaring_bitmap_set_copy_on_write(answer, is_cow(x1) || is_cow(x2));
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            container_t *c;
            if (bitsetconversion &&
                (get_container_type(c1, type1) != BITSET_CONTAINER_TYPE) &&
                (get_container_type(c2, type2) != BITSET_CONTAINER_TYPE)
            ){
                container_t *newc1 =
                    container_mutable_unwrap_shared(c1, &type1);
                newc1 = container_to_bitset(newc1, type1);
                type1 = BITSET_CONTAINER_TYPE;
                c = container_lazy_ior(newc1, type1, c2, type2,
                                       &result_type);
                if (c != newc1) {  // should not happen
                    container_free(newc1, type1);
                }
            } else {
                c = container_lazy_or(c1, type1, c2, type2, &result_type);
            }
            // since we assume that the initial containers are non-empty,
            // the
            // result here
            // can only be non-empty
            ra_append(&answer->high_low_container, s1, c, result_type);
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            c1 = get_copy_of_container(c1, &type1, is_cow(x1));
            if (is_cow(x1)) {
                ra_set_container_at_index(&x1->high_low_container, pos1, c1,
                                          type1);
            }
            ra_append(&answer->high_low_container, s1, c1, type1);
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }
            ra_append(&answer->high_low_container, s2, c2, type2);
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&answer->high_low_container,
                             &x2->high_low_container, pos2, length2,
                             is_cow(x2));
    } else if (pos2 == length2) {
        ra_append_copy_range(&answer->high_low_container,
                             &x1->high_low_container, pos1, length1,
                             is_cow(x1));
    }
    return answer;
}

static void roaring_bitmap_lazy_or_inplace(roaring_bitmap_t *x1,
                                    const roaring_bitmap_t *x2,
                                    const bool bitsetconversion) {
    uint8_t result_type = 0;
    int length1 = x1->high_low_container.size;
    const int length2 = x2->high_low_container.size;

    if (0 == length2) return;

    if (0 == length1) {
        roaring_bitmap_overwrite(x1, x2);
        return;
    }
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            if (!container_is_full(c1, type1)) {
                if ((bitsetconversion == false) ||
                    (get_container_type(c1, type1) == BITSET_CONTAINER_TYPE)
                ){
                    c1 = get_writable_copy_if_shared(c1, &type1);
                } else {
                    // convert to bitset
                    container_t *old_c1 = c1;
                    uint8_t old_type1 = type1;
                    c1 = container_mutable_unwrap_shared(c1, &type1);
                    c1 = container_to_bitset(c1, type1);
                    container_free(old_c1, old_type1);
                    type1 = BITSET_CONTAINER_TYPE;
                }

                container_t *c2 = ra_get_container_at_index(
                                        &x2->high_low_container, pos2, &type2);
                container_t *c = container_lazy_ior(c1, type1, c2, type2,
                                                    &result_type);

                if (c != c1) {  // in this instance a new container was created,
                                // and we need to free the old one
                    container_free(c1, type1);
                }

                ra_set_container_at_index(&x1->high_low_container, pos1, c,
                                          result_type);
            }
            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            // container_t *c2_clone = container_clone(c2, type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }
            ra_insert_new_key_value_at(&x1->high_low_container, pos1, s2, c2,
                                       type2);
            pos1++;
            length1++;
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&x1->high_low_container, &x2->high_low_container,
                             pos2, length2, is_cow(x2));
    }
}

static roaring_bitmap_t *roaring_bitmap_lazy_xor(const roaring_bitmap_t *x1,
                                          const roaring_bitmap_t *x2) {
    uint8_t result_type = 0;
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    if (0 == length1) {
        return roaring_bitmap_copy(x2);
    }
    if (0 == length2) {
        return roaring_bitmap_copy(x1);
    }
    roaring_bitmap_t *answer =
        roaring_bitmap_create_with_capacity(length1 + length2);
    roaring_bitmap_set_copy_on_write(answer, is_cow(x1) || is_cow(x2));
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            container_t *c = container_lazy_xor(
                                    c1, type1, c2, type2, &result_type);

            if (container_nonzero_cardinality(c, result_type)) {
                ra_append(&answer->high_low_container, s1, c, result_type);
            } else {
                container_free(c, result_type);
            }

            ++pos1;
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            c1 = get_copy_of_container(c1, &type1, is_cow(x1));
            if (is_cow(x1)) {
                ra_set_container_at_index(&x1->high_low_container, pos1, c1,
                                          type1);
            }
            ra_append(&answer->high_low_container, s1, c1, type1);
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }
            ra_append(&answer->high_low_container, s2, c2, type2);
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&answer->high_low_container,
                             &x2->high_low_container, pos2, length2,
                             is_cow(x2));
    } else if (pos2 == length2) {
        ra_append_copy_range(&answer->high_low_container,
                             &x1->high_low_container, pos1, length1,
                             is_cow(x1));
    }
    return answer;
}

static void roaring_bitmap_lazy_xor_inplace(roaring_bitmap_t *x1,
                                     const roaring_bitmap_t *x2) {
    assert(x1 != x2);
    uint8_t result_type = 0;
    int length1 = x1->high_low_container.size;
    const int length2 = x2->high_low_container.size;

    if (0 == length2) return;

    if (0 == length1) {
        roaring_bitmap_overwrite(x1, x2);
        return;
    }
    int pos1 = 0, pos2 = 0;
    uint8_t type1, type2;
    uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
    uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
    while (true) {
        if (s1 == s2) {
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);

            // We do the computation "in place" only when c1 is not a shared container.
            // Rationale: using a shared container safely with in place computation would
            // require making a copy and then doing the computation in place which is likely
            // less efficient than avoiding in place entirely and always generating a new
            // container.

            container_t *c;
            if (type1 == SHARED_CONTAINER_TYPE) {
                c = container_lazy_xor(c1, type1, c2, type2, &result_type);
                shared_container_free(CAST_shared(c1));  // release
            }
            else {
                c = container_lazy_ixor(c1, type1, c2, type2, &result_type);
            }

            if (container_nonzero_cardinality(c, result_type)) {
                ra_set_container_at_index(&x1->high_low_container, pos1, c,
                                          result_type);
                ++pos1;
            } else {
                container_free(c, result_type);
                ra_remove_at_index(&x1->high_low_container, pos1);
                --length1;
            }
            ++pos2;
            if (pos1 == length1) break;
            if (pos2 == length2) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        } else if (s1 < s2) {  // s1 < s2
            pos1++;
            if (pos1 == length1) break;
            s1 = ra_get_key_at_index(&x1->high_low_container, pos1);

        } else {  // s1 > s2
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            // container_t *c2_clone = container_clone(c2, type2);
            c2 = get_copy_of_container(c2, &type2, is_cow(x2));
            if (is_cow(x2)) {
                ra_set_container_at_index(&x2->high_low_container, pos2, c2,
                                          type2);
            }
            ra_insert_new_key_value_at(&x1->high_low_container, pos1, s2, c2,
                                       type2);
            pos1++;
            length1++;
            pos2++;
            if (pos2 == length2) break;
            s2 = ra_get_key_at_index(&x2->high_low_container, pos2);
        }
    }
    if (pos1 == length1) {
        ra_append_copy_range(&x1->high_low_container, &x2->high_low_container,
                             pos2, length2, is_cow(x2));
    }
}

static void roaring_bitmap_repair_after_lazy(roaring_bitmap_t *r) {
    roaring_array_t *ra = &r->high_low_container;

    int i = 0; for (i = 0; i < ra->size; ++i) {
        const uint8_t old_type = ra->typecodes[i];
        container_t *old_c = ra->containers[i];
        uint8_t new_type = old_type;
        container_t *new_c = container_repair_after_lazy(old_c, &new_type);
        ra->containers[i] = new_c;
        ra->typecodes[i] = new_type;
    }
}



/**
* roaring_bitmap_rank returns the number of integers that are smaller or equal
* to x.
*/
static uint64_t roaring_bitmap_rank(const roaring_bitmap_t *bm, uint32_t x) {
    uint64_t size = 0;
    uint32_t xhigh = x >> 16;
    int i = 0; for (i = 0; i < bm->high_low_container.size; i++) {
        uint32_t key = bm->high_low_container.keys[i];
        if (xhigh > key) {
            size +=
                container_get_cardinality(bm->high_low_container.containers[i],
                                          bm->high_low_container.typecodes[i]);
        } else if (xhigh == key) {
            return size + container_rank(bm->high_low_container.containers[i],
                                         bm->high_low_container.typecodes[i],
                                         x & 0xFFFF);
        } else {
            return size;
        }
    }
    return size;
}

/**
* roaring_bitmap_smallest returns the smallest value in the set.
* Returns UINT32_MAX if the set is empty.
*/
static uint32_t roaring_bitmap_minimum(const roaring_bitmap_t *bm) {
    if (bm->high_low_container.size > 0) {
        container_t *c = bm->high_low_container.containers[0];
        uint8_t type = bm->high_low_container.typecodes[0];
        uint32_t key = bm->high_low_container.keys[0];
        uint32_t lowvalue = container_minimum(c, type);
        return lowvalue | (key << 16);
    }
    return UINT32_MAX;
}

/**
* roaring_bitmap_smallest returns the greatest value in the set.
* Returns 0 if the set is empty.
*/
static uint32_t roaring_bitmap_maximum(const roaring_bitmap_t *bm) {
    if (bm->high_low_container.size > 0) {
        container_t *container =
            bm->high_low_container.containers[bm->high_low_container.size - 1];
        uint8_t typecode =
            bm->high_low_container.typecodes[bm->high_low_container.size - 1];
        uint32_t key =
            bm->high_low_container.keys[bm->high_low_container.size - 1];
        uint32_t lowvalue = container_maximum(container, typecode);
        return lowvalue | (key << 16);
    }
    return 0;
}

static bool roaring_bitmap_select(const roaring_bitmap_t *bm, uint32_t rank,
                           uint32_t *element) {
    container_t *container;
    uint8_t typecode;
    uint16_t key;
    uint32_t start_rank = 0;
    int i = 0;
    bool valid = false;
    while (!valid && i < bm->high_low_container.size) {
        container = bm->high_low_container.containers[i];
        typecode = bm->high_low_container.typecodes[i];
        valid =
            container_select(container, typecode, &start_rank, rank, element);
        i++;
    }

    if (valid) {
        key = bm->high_low_container.keys[i - 1];
        *element |= (((uint32_t)key) << 16);  // w/o cast, key promotes signed
        return true;
    } else
        return false;
}

static bool roaring_bitmap_intersect(const roaring_bitmap_t *x1,
                                     const roaring_bitmap_t *x2) {
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    uint64_t answer = 0;
    int pos1 = 0, pos2 = 0;

    while (pos1 < length1 && pos2 < length2) {
        const uint16_t s1 = ra_get_key_at_index(& x1->high_low_container, pos1);
        const uint16_t s2 = ra_get_key_at_index(& x2->high_low_container, pos2);

        if (s1 == s2) {
            uint8_t type1, type2;
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            if (container_intersect(c1, type1, c2, type2))
                return true;
            ++pos1;
            ++pos2;
        } else if (s1 < s2) {  // s1 < s2
            pos1 = ra_advance_until(& x1->high_low_container, s2, pos1);
        } else {  // s1 > s2
            pos2 = ra_advance_until(& x2->high_low_container, s1, pos2);
        }
    }
    return answer != 0;
}

static bool roaring_bitmap_intersect_with_range(const roaring_bitmap_t *bm,
                                         uint64_t x, uint64_t y) {
    if (x >= y) {
        // Empty range.
        return false;
    }
    roaring_uint32_iterator_t it;
    roaring_init_iterator(bm, &it);
    if (!roaring_move_uint32_iterator_equalorlarger(&it, x)) {
        // No values above x.
        return false;
    }
    if (it.current_value >= y) {
        // No values below y.
        return false;
    }
    return true;
}


static uint64_t roaring_bitmap_and_cardinality(const roaring_bitmap_t *x1,
                                        const roaring_bitmap_t *x2) {
    const int length1 = x1->high_low_container.size,
              length2 = x2->high_low_container.size;
    uint64_t answer = 0;
    int pos1 = 0, pos2 = 0;

    while (pos1 < length1 && pos2 < length2) {
        const uint16_t s1 = ra_get_key_at_index(&x1->high_low_container, pos1);
        const uint16_t s2 = ra_get_key_at_index(&x2->high_low_container, pos2);

        if (s1 == s2) {
            uint8_t type1, type2;
            container_t *c1 = ra_get_container_at_index(
                                    &x1->high_low_container, pos1, &type1);
            container_t *c2 = ra_get_container_at_index(
                                    &x2->high_low_container, pos2, &type2);
            answer += container_and_cardinality(c1, type1, c2, type2);
            ++pos1;
            ++pos2;
        } else if (s1 < s2) {  // s1 < s2
            pos1 = ra_advance_until(&x1->high_low_container, s2, pos1);
        } else {  // s1 > s2
            pos2 = ra_advance_until(&x2->high_low_container, s1, pos2);
        }
    }
    return answer;
}

static double roaring_bitmap_jaccard_index(const roaring_bitmap_t *x1,
                                    const roaring_bitmap_t *x2) {
    const uint64_t c1 = roaring_bitmap_get_cardinality(x1);
    const uint64_t c2 = roaring_bitmap_get_cardinality(x2);
    const uint64_t inter = roaring_bitmap_and_cardinality(x1, x2);
    return (double)inter / (double)(c1 + c2 - inter);
}

static uint64_t roaring_bitmap_or_cardinality(const roaring_bitmap_t *x1,
                                       const roaring_bitmap_t *x2) {
    const uint64_t c1 = roaring_bitmap_get_cardinality(x1);
    const uint64_t c2 = roaring_bitmap_get_cardinality(x2);
    const uint64_t inter = roaring_bitmap_and_cardinality(x1, x2);
    return c1 + c2 - inter;
}

static uint64_t roaring_bitmap_andnot_cardinality(const roaring_bitmap_t *x1,
                                           const roaring_bitmap_t *x2) {
    const uint64_t c1 = roaring_bitmap_get_cardinality(x1);
    const uint64_t inter = roaring_bitmap_and_cardinality(x1, x2);
    return c1 - inter;
}

static uint64_t roaring_bitmap_xor_cardinality(const roaring_bitmap_t *x1,
                                        const roaring_bitmap_t *x2) {
    const uint64_t c1 = roaring_bitmap_get_cardinality(x1);
    const uint64_t c2 = roaring_bitmap_get_cardinality(x2);
    const uint64_t inter = roaring_bitmap_and_cardinality(x1, x2);
    return c1 + c2 - 2 * inter;
}


static bool roaring_bitmap_contains(const roaring_bitmap_t *r, uint32_t val) {
    const uint16_t hb = val >> 16;
    /*
     * the next function call involves a binary search and lots of branching.
     */
    int32_t i = ra_get_index(&r->high_low_container, hb);
    if (i < 0) return false;

    uint8_t typecode;
    // next call ought to be cheap
    container_t *container =
        ra_get_container_at_index(&r->high_low_container, i, &typecode);
    // rest might be a tad expensive, possibly involving another round of binary search
    return container_contains(container, val & 0xFFFF, typecode);
}


/**
 * Check whether a range of values from range_start (included) to range_end (excluded) is present
 */
static bool roaring_bitmap_contains_range(const roaring_bitmap_t *r, uint64_t range_start, uint64_t range_end) {
    if(range_end >= UINT64_C(0x100000000)) {
        range_end = UINT64_C(0x100000000);
    }
    if (range_start >= range_end) return true;  // empty range are always contained!
    if (range_end - range_start == 1) return roaring_bitmap_contains(r, (uint32_t)range_start);
    uint16_t hb_rs = (uint16_t)(range_start >> 16);
    uint16_t hb_re = (uint16_t)((range_end - 1) >> 16);
    const int32_t span = hb_re - hb_rs;
    const int32_t hlc_sz = ra_get_size(&r->high_low_container);
    if (hlc_sz < span + 1) {
      return false;
    }
    int32_t is = ra_get_index(&r->high_low_container, hb_rs);
    int32_t ie = ra_get_index(&r->high_low_container, hb_re);
    ie = (ie < 0 ? -ie - 1 : ie);
    if ((is < 0) || ((ie - is) != span)) {
       return false;
    }
    const uint32_t lb_rs = range_start & 0xFFFF;
    const uint32_t lb_re = ((range_end - 1) & 0xFFFF) + 1;
    uint8_t type;
    container_t *c = ra_get_container_at_index(&r->high_low_container, is,
                                               &type);
    if (hb_rs == hb_re) {
      return container_contains_range(c, lb_rs, lb_re, type);
    }
    if (!container_contains_range(c, lb_rs, 1 << 16, type)) {
      return false;
    }
    assert(ie < hlc_sz); // would indicate an algorithmic bug
    c = ra_get_container_at_index(&r->high_low_container, ie, &type);
    if (!container_contains_range(c, 0, lb_re, type)) {
        return false;
    }
    int32_t i; for (i = is + 1; i < ie; ++i) {
        c = ra_get_container_at_index(&r->high_low_container, i, &type);
        if (!container_is_full(c, type) ) {
          return false;
        }
    }
    return true;
}


static bool roaring_bitmap_is_strict_subset(const roaring_bitmap_t *r1,
                                     const roaring_bitmap_t *r2) {
    return (roaring_bitmap_get_cardinality(r2) >
                roaring_bitmap_get_cardinality(r1) &&
            roaring_bitmap_is_subset(r1, r2));
}


/*
 * FROZEN SERIALIZATION FORMAT DESCRIPTION
 *
 * -- (beginning must be aligned by 32 bytes) --
 * <bitset_data> uint64_t[BITSET_CONTAINER_SIZE_IN_WORDS * num_bitset_containers]
 * <run_data>    rle16_t[total number of rle elements in all run containers]
 * <array_data>  uint16_t[total number of array elements in all array containers]
 * <keys>        uint16_t[num_containers]
 * <counts>      uint16_t[num_containers]
 * <typecodes>   uint8_t[num_containers]
 * <header>      uint32_t
 *
 * <header> is a 4-byte value which is a bit union of FROZEN_COOKIE (15 bits)
 * and the number of containers (17 bits).
 *
 * <counts> stores number of elements for every container.
 * Its meaning depends on container type.
 * For array and bitset containers, this value is the container cardinality minus one.
 * For run container, it is the number of rle_t elements (n_runs).
 *
 * <bitset_data>,<array_data>,<run_data> are flat arrays of elements of
 * all containers of respective type.
 *
 * <*_data> and <keys> are kept close together because they are not accessed
 * during deserilization. This may reduce IO in case of large mmaped bitmaps.
 * All members have their native alignments during deserilization except <header>,
 * which is not guaranteed to be aligned by 4 bytes.
 */

static size_t roaring_bitmap_frozen_size_in_bytes(const roaring_bitmap_t *rb) {
    const roaring_array_t *ra = &rb->high_low_container;
    size_t num_bytes = 0;
    int32_t i; for (i = 0; i < ra->size; i++) {
        switch (ra->typecodes[i]) {
            case BITSET_CONTAINER_TYPE: {
                num_bytes += BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);
                break;
            }
            case RUN_CONTAINER_TYPE: {
                const run_container_t *rc = const_CAST_run(ra->containers[i]);
                num_bytes += rc->n_runs * sizeof(rle16_t);
                break;
            }
            case ARRAY_CONTAINER_TYPE: {
                const array_container_t *ac =
                        const_CAST_array(ra->containers[i]);
                num_bytes += ac->cardinality * sizeof(uint16_t);
                break;
            }
            default:
                __builtin_unreachable();
        }
    }
    num_bytes += (2 + 2 + 1) * ra->size; // keys, counts, typecodes
    num_bytes += 4; // header
    return num_bytes;
}

static inline  void *arena_alloc(char **arena, size_t num_bytes) {
    char *res = *arena;
    *arena += num_bytes;
    return res;
}

static void roaring_bitmap_frozen_serialize(const roaring_bitmap_t *rb, char *buf) {
    /*
     * Note: we do not require user to supply a specifically aligned buffer.
     * Thus we have to use memcpy() everywhere.
     */

    const roaring_array_t *ra = &rb->high_low_container;

    size_t bitset_zone_size = 0;
    size_t run_zone_size = 0;
    size_t array_zone_size = 0;
    int32_t i; for (i = 0; i < ra->size; i++) {
        switch (ra->typecodes[i]) {
            case BITSET_CONTAINER_TYPE: {
                bitset_zone_size +=
                        BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);
                break;
            }
            case RUN_CONTAINER_TYPE: {
                const run_container_t *rc = const_CAST_run(ra->containers[i]);
                run_zone_size += rc->n_runs * sizeof(rle16_t);
                break;
            }
            case ARRAY_CONTAINER_TYPE: {
                const array_container_t *ac =
                        const_CAST_array(ra->containers[i]);
                array_zone_size += ac->cardinality * sizeof(uint16_t);
                break;
            }
            default:
                __builtin_unreachable();
        }
    }

    uint64_t *bitset_zone = (uint64_t *)arena_alloc(&buf, bitset_zone_size);
    rle16_t *run_zone = (rle16_t *)arena_alloc(&buf, run_zone_size);
    uint16_t *array_zone = (uint16_t *)arena_alloc(&buf, array_zone_size);
    uint16_t *key_zone = (uint16_t *)arena_alloc(&buf, 2*ra->size);
    uint16_t *count_zone = (uint16_t *)arena_alloc(&buf, 2*ra->size);
    uint8_t *typecode_zone = (uint8_t *)arena_alloc(&buf, ra->size);
    uint32_t *header_zone = (uint32_t *)arena_alloc(&buf, 4);

    for (i = 0; i < ra->size; i++) {
        uint16_t count;
        switch (ra->typecodes[i]) {
            case BITSET_CONTAINER_TYPE: {
                const bitset_container_t *bc =
                            const_CAST_bitset(ra->containers[i]);
                memcpy(bitset_zone, bc->words,
                       BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t));
                bitset_zone += BITSET_CONTAINER_SIZE_IN_WORDS;
                if (bc->cardinality != BITSET_UNKNOWN_CARDINALITY) {
                    count = bc->cardinality - 1;
                } else {
                    count = bitset_container_compute_cardinality(bc) - 1;
                }
                break;
            }
            case RUN_CONTAINER_TYPE: {
                const run_container_t *rc = const_CAST_run(ra->containers[i]);
                size_t num_bytes = rc->n_runs * sizeof(rle16_t);
                memcpy(run_zone, rc->runs, num_bytes);
                run_zone += rc->n_runs;
                count = rc->n_runs;
                break;
            }
            case ARRAY_CONTAINER_TYPE: {
                const array_container_t *ac =
                            const_CAST_array(ra->containers[i]);
                size_t num_bytes = ac->cardinality * sizeof(uint16_t);
                memcpy(array_zone, ac->array, num_bytes);
                array_zone += ac->cardinality;
                count = ac->cardinality - 1;
                break;
            }
            default:
                __builtin_unreachable();
        }
        memcpy(&count_zone[i], &count, 2);
    }
    memcpy(key_zone, ra->keys, ra->size * sizeof(uint16_t));
    memcpy(typecode_zone, ra->typecodes, ra->size * sizeof(uint8_t));
    uint32_t header = ((uint32_t)ra->size << 15) | FROZEN_COOKIE;
    memcpy(header_zone, &header, 4);
}

static const roaring_bitmap_t *
roaring_bitmap_frozen_view(const char *buf, size_t length) {
    if ((uintptr_t)buf % 32 != 0) {
        return NULL;
    }

    // cookie and num_containers
    if (length < 4) {
        return NULL;
    }
    uint32_t header;
    memcpy(&header, buf + length - 4, 4); // header may be misaligned
    if ((header & 0x7FFF) != FROZEN_COOKIE) {
        return NULL;
    }
    int32_t num_containers = (header >> 15);

    // typecodes, counts and keys
    if (length < 4 + (size_t)num_containers * (1 + 2 + 2)) {
        return NULL;
    }
    uint16_t *keys = (uint16_t *)(buf + length - 4 - num_containers * 5);
    uint16_t *counts = (uint16_t *)(buf + length - 4 - num_containers * 3);
    uint8_t *typecodes = (uint8_t *)(buf + length - 4 - num_containers * 1);

    // {bitset,array,run}_zone
    int32_t num_bitset_containers = 0;
    int32_t num_run_containers = 0;
    int32_t num_array_containers = 0;
    size_t bitset_zone_size = 0;
    size_t run_zone_size = 0;
    size_t array_zone_size = 0;
    int32_t i; for (i = 0; i < num_containers; i++) {
        switch (typecodes[i]) {
            case BITSET_CONTAINER_TYPE:
                num_bitset_containers++;
                bitset_zone_size += BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t);
                break;
            case RUN_CONTAINER_TYPE:
                num_run_containers++;
                run_zone_size += counts[i] * sizeof(rle16_t);
                break;
            case ARRAY_CONTAINER_TYPE:
                num_array_containers++;
                array_zone_size += (counts[i] + UINT32_C(1)) * sizeof(uint16_t);
                break;
            default:
                return NULL;
        }
    }
    if (length != bitset_zone_size + run_zone_size + array_zone_size +
                  5 * num_containers + 4) {
        return NULL;
    }
    uint64_t *bitset_zone = (uint64_t*) (buf);
    rle16_t *run_zone = (rle16_t*) (buf + bitset_zone_size);
    uint16_t *array_zone = (uint16_t*) (buf + bitset_zone_size + run_zone_size);

    size_t alloc_size = 0;
    alloc_size += sizeof(roaring_bitmap_t);
    alloc_size += num_containers * sizeof(container_t*);
    alloc_size += num_bitset_containers * sizeof(bitset_container_t);
    alloc_size += num_run_containers * sizeof(run_container_t);
    alloc_size += num_array_containers * sizeof(array_container_t);

    char *arena = (char *)ndpi_malloc(alloc_size);
    if (arena == NULL) {
        return NULL;
    }

    roaring_bitmap_t *rb = (roaring_bitmap_t *)
            arena_alloc(&arena, sizeof(roaring_bitmap_t));
    rb->high_low_container.flags = ROARING_FLAG_FROZEN;
    rb->high_low_container.allocation_size = num_containers;
    rb->high_low_container.size = num_containers;
    rb->high_low_container.keys = (uint16_t *)keys;
    rb->high_low_container.typecodes = (uint8_t *)typecodes;
    rb->high_low_container.containers =
        (container_t **)arena_alloc(&arena,
                                    sizeof(container_t*) * num_containers);
     for (i = 0; i < num_containers; i++) {
        switch (typecodes[i]) {
            case BITSET_CONTAINER_TYPE: {
                bitset_container_t *bitset = (bitset_container_t *)
                        arena_alloc(&arena, sizeof(bitset_container_t));
                bitset->words = bitset_zone;
                bitset->cardinality = counts[i] + UINT32_C(1);
                rb->high_low_container.containers[i] = bitset;
                bitset_zone += BITSET_CONTAINER_SIZE_IN_WORDS;
                break;
            }
            case RUN_CONTAINER_TYPE: {
                run_container_t *run = (run_container_t *)
                        arena_alloc(&arena, sizeof(run_container_t));
                run->capacity = counts[i];
                run->n_runs = counts[i];
                run->runs = run_zone;
                rb->high_low_container.containers[i] = run;
                run_zone += run->n_runs;
                break;
            }
            case ARRAY_CONTAINER_TYPE: {
                array_container_t *array = (array_container_t *)
                        arena_alloc(&arena, sizeof(array_container_t));
                array->capacity = counts[i] + UINT32_C(1);
                array->cardinality = counts[i] + UINT32_C(1);
                array->array = array_zone;
                rb->high_low_container.containers[i] = array;
                array_zone += counts[i] + UINT32_C(1);
                break;
            }
            default:
                ndpi_free(arena);
                return NULL;
        }
    }

    return rb;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring {
#endif
/* end file src/roaring.c */
/* begin file src/array_util.c */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

extern inline int32_t binarySearch(const uint16_t *array, int32_t lenarray,
                                   uint16_t ikey);

#ifdef CROARING_IS_X64
// used by intersect_vector16
ALIGNED(0x1000)
static const uint8_t shuffle_mask16[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    6,    7,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    6,    7,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    6,    7,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    6,    7,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    6,    7,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    6,    7,    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    8,    9,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    8,    9,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    8,    9,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    8,    9,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    6,    7,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,    8,    9,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,
    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    6,    7,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,    8,    9,    0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    6,    7,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    6,    7,    8,    9,    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,
    8,    9,    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    10,   11,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    6,    7,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    6,    7,    10,   11,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    6,    7,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    6,    7,    10,   11,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    6,    7,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    8,    9,    10,   11,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    8,    9,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    8,    9,    10,   11,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    8,    9,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    8,    9,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    6,    7,    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,    8,    9,    10,   11,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    6,    7,    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    6,    7,    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    6,    7,    8,    9,
    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    6,    7,    8,    9,    10,   11,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,
    0xFF, 0xFF, 0xFF, 0xFF, 12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    6,    7,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    6,    7,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    6,    7,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    6,    7,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 8,    9,    12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    8,    9,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    8,    9,    12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    8,    9,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    8,    9,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,
    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    6,    7,    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    6,    7,    8,    9,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,
    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    6,    7,    8,    9,    12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    6,    7,    8,    9,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    6,    7,    8,    9,    12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    10,   11,   12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    10,   11,   12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    6,    7,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,    10,   11,   12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    6,    7,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    6,    7,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    6,    7,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    6,    7,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    6,    7,    10,   11,   12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 8,    9,    10,   11,   12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    8,    9,
    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    8,    9,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    8,    9,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    8,    9,
    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    8,    9,    10,   11,   12,   13,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    8,    9,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    8,    9,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    6,    7,    8,    9,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,    8,    9,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,
    8,    9,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    6,    7,    8,    9,    10,   11,   12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,    8,    9,    10,   11,
    12,   13,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    6,    7,    8,    9,    10,   11,   12,   13,   0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,   12,   13,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,
    8,    9,    10,   11,   12,   13,   0xFF, 0xFF, 14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    6,    7,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    6,    7,    14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    6,    7,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    6,    7,    14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    6,    7,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    8,    9,    14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    8,    9,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    8,    9,    14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    8,    9,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    8,    9,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    6,    7,    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,    8,    9,    14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    6,    7,    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    6,    7,    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    6,    7,    8,    9,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    6,    7,    8,    9,    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    10,   11,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    10,   11,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    6,    7,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,
    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    6,    7,    10,   11,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    6,    7,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    6,    7,    10,   11,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,
    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 8,    9,    10,   11,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    8,    9,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    8,    9,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    8,    9,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    8,    9,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    8,    9,    10,   11,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    8,    9,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    8,    9,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    8,    9,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,
    8,    9,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    6,    7,    8,    9,    10,   11,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    6,    7,    8,    9,
    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,
    8,    9,    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    6,    7,    8,    9,    10,   11,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    6,    7,    8,    9,
    10,   11,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    6,    7,    8,    9,    10,   11,   14,   15,   0xFF, 0xFF,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    12,   13,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    12,   13,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    6,    7,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,    12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    6,    7,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    6,    7,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    6,    7,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    6,    7,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    6,    7,    12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 8,    9,    12,   13,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    8,    9,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    8,    9,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    8,    9,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    8,    9,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    8,    9,    12,   13,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    8,    9,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    8,    9,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    6,    7,    8,    9,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,    8,    9,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,
    8,    9,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    6,    7,    8,    9,    12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,    8,    9,    12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    6,    7,    8,    9,    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    6,    7,    8,    9,    12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    6,    7,
    8,    9,    12,   13,   14,   15,   0xFF, 0xFF, 10,   11,   12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    4,    5,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    10,   11,   12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 6,    7,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    6,    7,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    6,    7,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    6,    7,    10,   11,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    6,    7,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    4,    5,    6,    7,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    4,    5,    6,    7,    10,   11,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    4,    5,    6,    7,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF,
    8,    9,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    8,    9,    10,   11,   12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    8,    9,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    2,    3,    8,    9,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 4,    5,    8,    9,    10,   11,   12,   13,
    14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,
    8,    9,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF,
    2,    3,    4,    5,    8,    9,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,    4,    5,    8,    9,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 6,    7,    8,    9,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0,    1,    6,    7,    8,    9,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 2,    3,    6,    7,    8,    9,    10,   11,
    12,   13,   14,   15,   0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    2,    3,
    6,    7,    8,    9,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF,
    4,    5,    6,    7,    8,    9,    10,   11,   12,   13,   14,   15,
    0xFF, 0xFF, 0xFF, 0xFF, 0,    1,    4,    5,    6,    7,    8,    9,
    10,   11,   12,   13,   14,   15,   0xFF, 0xFF, 2,    3,    4,    5,
    6,    7,    8,    9,    10,   11,   12,   13,   14,   15,   0xFF, 0xFF,
    0,    1,    2,    3,    4,    5,    6,    7,    8,    9,    10,   11,
    12,   13,   14,   15};

/**
 * From Schlegel et al., Fast Sorted-Set Intersection using SIMD Instructions
 * Optimized by D. Lemire on May 3rd 2013
 */
CROARING_TARGET_AVX2
static int32_t intersect_vector16(const uint16_t *__restrict__ A, size_t s_a,
                           const uint16_t *__restrict__ B, size_t s_b,
                           uint16_t *C) {
    size_t count = 0;
    size_t i_a = 0, i_b = 0;
    const int vectorlength = sizeof(__m128i) / sizeof(uint16_t);
    const size_t st_a = (s_a / vectorlength) * vectorlength;
    const size_t st_b = (s_b / vectorlength) * vectorlength;
    __m128i v_a, v_b;
    if ((i_a < st_a) && (i_b < st_b)) {
        v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
        v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
        while ((A[i_a] == 0) || (B[i_b] == 0)) {
            const __m128i res_v = _mm_cmpestrm(
                v_b, vectorlength, v_a, vectorlength,
                _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_BIT_MASK);
            const int r = _mm_extract_epi32(res_v, 0);
            __m128i sm16 = _mm_load_si128((const __m128i *)shuffle_mask16 + r);
            __m128i p = _mm_shuffle_epi8(v_a, sm16);
            _mm_storeu_si128((__m128i *)&C[count], p);  // can overflow
            count += _mm_popcnt_u32(r);
            const uint16_t a_max = A[i_a + vectorlength - 1];
            const uint16_t b_max = B[i_b + vectorlength - 1];
            if (a_max <= b_max) {
                i_a += vectorlength;
                if (i_a == st_a) break;
                v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
            }
            if (b_max <= a_max) {
                i_b += vectorlength;
                if (i_b == st_b) break;
                v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
            }
        }
        if ((i_a < st_a) && (i_b < st_b))
            while (true) {
                const __m128i res_v = _mm_cmpistrm(
                    v_b, v_a,
                    _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_BIT_MASK);
                const int r = _mm_extract_epi32(res_v, 0);
                __m128i sm16 =
                    _mm_load_si128((const __m128i *)shuffle_mask16 + r);
                __m128i p = _mm_shuffle_epi8(v_a, sm16);
                _mm_storeu_si128((__m128i *)&C[count], p);  // can overflow
                count += _mm_popcnt_u32(r);
                const uint16_t a_max = A[i_a + vectorlength - 1];
                const uint16_t b_max = B[i_b + vectorlength - 1];
                if (a_max <= b_max) {
                    i_a += vectorlength;
                    if (i_a == st_a) break;
                    v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
                }
                if (b_max <= a_max) {
                    i_b += vectorlength;
                    if (i_b == st_b) break;
                    v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
                }
            }
    }
    // intersect the tail using scalar intersection
    while (i_a < s_a && i_b < s_b) {
        uint16_t a = A[i_a];
        uint16_t b = B[i_b];
        if (a < b) {
            i_a++;
        } else if (b < a) {
            i_b++;
        } else {
            C[count] = a;  //==b;
            count++;
            i_a++;
            i_b++;
        }
    }
    return (int32_t)count;
}
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
static int32_t intersect_vector16_cardinality(const uint16_t *__restrict__ A,
                                       size_t s_a,
                                       const uint16_t *__restrict__ B,
                                       size_t s_b) {
    size_t count = 0;
    size_t i_a = 0, i_b = 0;
    const int vectorlength = sizeof(__m128i) / sizeof(uint16_t);
    const size_t st_a = (s_a / vectorlength) * vectorlength;
    const size_t st_b = (s_b / vectorlength) * vectorlength;
    __m128i v_a, v_b;
    if ((i_a < st_a) && (i_b < st_b)) {
        v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
        v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
        while ((A[i_a] == 0) || (B[i_b] == 0)) {
            const __m128i res_v = _mm_cmpestrm(
                v_b, vectorlength, v_a, vectorlength,
                _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_BIT_MASK);
            const int r = _mm_extract_epi32(res_v, 0);
            count += _mm_popcnt_u32(r);
            const uint16_t a_max = A[i_a + vectorlength - 1];
            const uint16_t b_max = B[i_b + vectorlength - 1];
            if (a_max <= b_max) {
                i_a += vectorlength;
                if (i_a == st_a) break;
                v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
            }
            if (b_max <= a_max) {
                i_b += vectorlength;
                if (i_b == st_b) break;
                v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
            }
        }
        if ((i_a < st_a) && (i_b < st_b))
            while (true) {
                const __m128i res_v = _mm_cmpistrm(
                    v_b, v_a,
                    _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY | _SIDD_BIT_MASK);
                const int r = _mm_extract_epi32(res_v, 0);
                count += _mm_popcnt_u32(r);
                const uint16_t a_max = A[i_a + vectorlength - 1];
                const uint16_t b_max = B[i_b + vectorlength - 1];
                if (a_max <= b_max) {
                    i_a += vectorlength;
                    if (i_a == st_a) break;
                    v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
                }
                if (b_max <= a_max) {
                    i_b += vectorlength;
                    if (i_b == st_b) break;
                    v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
                }
            }
    }
    // intersect the tail using scalar intersection
    while (i_a < s_a && i_b < s_b) {
        uint16_t a = A[i_a];
        uint16_t b = B[i_b];
        if (a < b) {
            i_a++;
        } else if (b < a) {
            i_b++;
        } else {
            count++;
            i_a++;
            i_b++;
        }
    }
    return (int32_t)count;
}
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
/////////
// Warning:
// This function may not be safe if A == C or B == C.
/////////
static int32_t difference_vector16(const uint16_t *__restrict__ A, size_t s_a,
                            const uint16_t *__restrict__ B, size_t s_b,
                            uint16_t *C) {
    // we handle the degenerate case
    if (s_a == 0) return 0;
    if (s_b == 0) {
        if (A != C) memcpy(C, A, sizeof(uint16_t) * s_a);
        return (int32_t)s_a;
    }
    // handle the leading zeroes, it is messy but it allows us to use the fast
    // _mm_cmpistrm instrinsic safely
    int32_t count = 0;
    if ((A[0] == 0) || (B[0] == 0)) {
        if ((A[0] == 0) && (B[0] == 0)) {
            A++;
            s_a--;
            B++;
            s_b--;
        } else if (A[0] == 0) {
            C[count++] = 0;
            A++;
            s_a--;
        } else {
            B++;
            s_b--;
        }
    }
    // at this point, we have two non-empty arrays, made of non-zero
    // increasing values.
    size_t i_a = 0, i_b = 0;
    const size_t vectorlength = sizeof(__m128i) / sizeof(uint16_t);
    const size_t st_a = (s_a / vectorlength) * vectorlength;
    const size_t st_b = (s_b / vectorlength) * vectorlength;
    if ((i_a < st_a) && (i_b < st_b)) {  // this is the vectorized code path
        __m128i v_a, v_b;                //, v_bmax;
        // we load a vector from A and a vector from B
        v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
        v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
        // we have a runningmask which indicates which values from A have been
        // spotted in B, these don't get written out.
        __m128i runningmask_a_found_in_b = _mm_setzero_si128();
        /****
        * start of the main vectorized loop
        *****/
        while (true) {
            // afoundinb will contain a mask indicate for each entry in A
            // whether it is seen
            // in B
            const __m128i a_found_in_b =
                _mm_cmpistrm(v_b, v_a, _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY |
                                           _SIDD_BIT_MASK);
            runningmask_a_found_in_b =
                _mm_or_si128(runningmask_a_found_in_b, a_found_in_b);
            // we always compare the last values of A and B
            const uint16_t a_max = A[i_a + vectorlength - 1];
            const uint16_t b_max = B[i_b + vectorlength - 1];
            if (a_max <= b_max) {
                // Ok. In this code path, we are ready to write our v_a
                // because there is no need to read more from B, they will
                // all be large values.
                const int bitmask_belongs_to_difference =
                    _mm_extract_epi32(runningmask_a_found_in_b, 0) ^ 0xFF;
                /*** next few lines are probably expensive *****/
                __m128i sm16 = _mm_load_si128((const __m128i *)shuffle_mask16 +
                                              bitmask_belongs_to_difference);
                __m128i p = _mm_shuffle_epi8(v_a, sm16);
                _mm_storeu_si128((__m128i *)&C[count], p);  // can overflow
                count += _mm_popcnt_u32(bitmask_belongs_to_difference);
                // we advance a
                i_a += vectorlength;
                if (i_a == st_a)  // no more
                    break;
                runningmask_a_found_in_b = _mm_setzero_si128();
                v_a = _mm_lddqu_si128((__m128i *)&A[i_a]);
            }
            if (b_max <= a_max) {
                // in this code path, the current v_b has become useless
                i_b += vectorlength;
                if (i_b == st_b) break;
                v_b = _mm_lddqu_si128((__m128i *)&B[i_b]);
            }
        }
        // at this point, either we have i_a == st_a, which is the end of the
        // vectorized processing,
        // or we have i_b == st_b,  and we are not done processing the vector...
        // so we need to finish it off.
        if (i_a < st_a) {        // we have unfinished business...
            uint16_t buffer[8];  // buffer to do a masked load
            memset(buffer, 0, 8 * sizeof(uint16_t));
            memcpy(buffer, B + i_b, (s_b - i_b) * sizeof(uint16_t));
            v_b = _mm_lddqu_si128((__m128i *)buffer);
            const __m128i a_found_in_b =
                _mm_cmpistrm(v_b, v_a, _SIDD_UWORD_OPS | _SIDD_CMP_EQUAL_ANY |
                                           _SIDD_BIT_MASK);
            runningmask_a_found_in_b =
                _mm_or_si128(runningmask_a_found_in_b, a_found_in_b);
            const int bitmask_belongs_to_difference =
                _mm_extract_epi32(runningmask_a_found_in_b, 0) ^ 0xFF;
            __m128i sm16 = _mm_load_si128((const __m128i *)shuffle_mask16 +
                                          bitmask_belongs_to_difference);
            __m128i p = _mm_shuffle_epi8(v_a, sm16);
            _mm_storeu_si128((__m128i *)&C[count], p);  // can overflow
            count += _mm_popcnt_u32(bitmask_belongs_to_difference);
            i_a += vectorlength;
        }
        // at this point we should have i_a == st_a and i_b == st_b
    }
    // do the tail using scalar code
    while (i_a < s_a && i_b < s_b) {
        uint16_t a = A[i_a];
        uint16_t b = B[i_b];
        if (b < a) {
            i_b++;
        } else if (a < b) {
            C[count] = a;
            count++;
            i_a++;
        } else {  //==
            i_a++;
            i_b++;
        }
    }
    if (i_a < s_a) {
        if(C == A) {
          assert((size_t)count <= i_a);
          if((size_t)count < i_a) {
            memmove(C + count, A + i_a, sizeof(uint16_t) * (s_a - i_a));
          }
        } else {
           for(size_t i = 0; i < (s_a - i_a); i++) {
                C[count + i] = A[i + i_a];
           }
        }
        count += (int32_t)(s_a - i_a);
    }
    return count;
}
CROARING_UNTARGET_REGION
#endif  // CROARING_IS_X64



/**
* Branchless binary search going after 4 values at once.
* Assumes that array is sorted.
* You have that array[*index1] >= target1, array[*index12] >= target2, ...
* except when *index1 = n, in which case you know that all values in array are
* smaller than target1, and so forth.
* It has logarithmic complexity.
*/
static void binarySearch4(const uint16_t *array, int32_t n, uint16_t target1,
                   uint16_t target2, uint16_t target3, uint16_t target4,
                   int32_t *index1, int32_t *index2, int32_t *index3,
                   int32_t *index4) {
  const uint16_t *base1 = array;
  const uint16_t *base2 = array;
  const uint16_t *base3 = array;
  const uint16_t *base4 = array;
  if (n == 0)
    return;
  while (n > 1) {
    int32_t half = n >> 1;
    base1 = (base1[half] < target1) ? &base1[half] : base1;
    base2 = (base2[half] < target2) ? &base2[half] : base2;
    base3 = (base3[half] < target3) ? &base3[half] : base3;
    base4 = (base4[half] < target4) ? &base4[half] : base4;
    n -= half;
  }
  *index1 = (int32_t)((*base1 < target1) + base1 - array);
  *index2 = (int32_t)((*base2 < target2) + base2 - array);
  *index3 = (int32_t)((*base3 < target3) + base3 - array);
  *index4 = (int32_t)((*base4 < target4) + base4 - array);
}

/**
* Branchless binary search going after 2 values at once.
* Assumes that array is sorted.
* You have that array[*index1] >= target1, array[*index12] >= target2.
* except when *index1 = n, in which case you know that all values in array are
* smaller than target1, and so forth.
* It has logarithmic complexity.
*/
static void binarySearch2(const uint16_t *array, int32_t n, uint16_t target1,
                   uint16_t target2, int32_t *index1, int32_t *index2) {
  const uint16_t *base1 = array;
  const uint16_t *base2 = array;
  if (n == 0)
    return;
  while (n > 1) {
    int32_t half = n >> 1;
    base1 = (base1[half] < target1) ? &base1[half] : base1;
    base2 = (base2[half] < target2) ? &base2[half] : base2;
    n -= half;
  }
  *index1 = (int32_t)((*base1 < target1) + base1 - array);
  *index2 = (int32_t)((*base2 < target2) + base2 - array);
}

/* Computes the intersection between one small and one large set of uint16_t.
 * Stores the result into buffer and return the number of elements.
 * Processes the small set in blocks of 4 values calling binarySearch4
 * and binarySearch2. This approach can be slightly superior to a conventional
 * galloping search in some instances.
 */
static int32_t intersect_skewed_uint16(const uint16_t *small_set, size_t size_s,
                                         const uint16_t *large, size_t size_l,
                                         uint16_t *buffer) {
  size_t pos = 0, idx_l = 0, idx_s = 0;

  if (0 == size_s) {
    return 0;
  }
  int32_t index1 = 0, index2 = 0, index3 = 0, index4 = 0;
  while ((idx_s + 4 <= size_s) && (idx_l < size_l)) {
    uint16_t target1 = small_set[idx_s];
    uint16_t target2 = small_set[idx_s + 1];
    uint16_t target3 = small_set[idx_s + 2];
    uint16_t target4 = small_set[idx_s + 3];
    binarySearch4(large + idx_l, (int32_t)(size_l - idx_l), target1, target2, target3,
                  target4, &index1, &index2, &index3, &index4);
    if ((index1 + idx_l < size_l) && (large[idx_l + index1] == target1)) {
      buffer[pos++] = target1;
    }
    if ((index2 + idx_l < size_l) && (large[idx_l + index2] == target2)) {
      buffer[pos++] = target2;
    }
    if ((index3 + idx_l < size_l) && (large[idx_l + index3] == target3)) {
      buffer[pos++] = target3;
    }
    if ((index4 + idx_l < size_l) && (large[idx_l + index4] == target4)) {
      buffer[pos++] = target4;
    }
    idx_s += 4;
    idx_l += index4;
  }
  if ((idx_s + 2 <= size_s) && (idx_l < size_l)) {
    uint16_t target1 = small_set[idx_s];
    uint16_t target2 = small_set[idx_s + 1];
    binarySearch2(large + idx_l, (int32_t)(size_l - idx_l), target1, target2, &index1,
                  &index2);
    if ((index1 + idx_l < size_l) && (large[idx_l + index1] == target1)) {
      buffer[pos++] = target1;
    }
    if ((index2 + idx_l < size_l) && (large[idx_l + index2] == target2)) {
      buffer[pos++] = target2;
    }
    idx_s += 2;
    idx_l += index2;
  }
  if ((idx_s < size_s) && (idx_l < size_l)) {
    uint16_t val_s = small_set[idx_s];
    int32_t index = binarySearch(large + idx_l, (int32_t)(size_l - idx_l), val_s);
    if (index >= 0)
      buffer[pos++] = val_s;
  }
  return (int32_t)pos;
}



// TODO: this could be accelerated, possibly, by using binarySearch4 as above.
static int32_t intersect_skewed_uint16_cardinality(const uint16_t *small_set,
                                            size_t size_s,
                                            const uint16_t *large,
                                            size_t size_l) {
    size_t pos = 0, idx_l = 0, idx_s = 0;

    if (0 == size_s) {
        return 0;
    }

    uint16_t val_l = large[idx_l], val_s = small_set[idx_s];

    while (true) {
        if (val_l < val_s) {
            idx_l = advanceUntil(large, (int32_t)idx_l, (int32_t)size_l, val_s);
            if (idx_l == size_l) break;
            val_l = large[idx_l];
        } else if (val_s < val_l) {
            idx_s++;
            if (idx_s == size_s) break;
            val_s = small_set[idx_s];
        } else {
            pos++;
            idx_s++;
            if (idx_s == size_s) break;
            val_s = small_set[idx_s];
            idx_l = advanceUntil(large, (int32_t)idx_l, (int32_t)size_l, val_s);
            if (idx_l == size_l) break;
            val_l = large[idx_l];
        }
    }

    return (int32_t)pos;
}

bool intersect_skewed_uint16_nonempty(const uint16_t *small_set, size_t size_s,
                                const uint16_t *large, size_t size_l) {
    size_t idx_l = 0, idx_s = 0;

    if (0 == size_s) {
        return false;
    }

    uint16_t val_l = large[idx_l], val_s = small_set[idx_s];

    while (true) {
        if (val_l < val_s) {
            idx_l = advanceUntil(large, (int32_t)idx_l, (int32_t)size_l, val_s);
            if (idx_l == size_l) break;
            val_l = large[idx_l];
        } else if (val_s < val_l) {
            idx_s++;
            if (idx_s == size_s) break;
            val_s = small_set[idx_s];
        } else {
            return true;
        }
    }

    return false;
}

/**
 * Generic intersection function.
 */
static int32_t intersect_uint16(const uint16_t *A, const size_t lenA,
                         const uint16_t *B, const size_t lenB, uint16_t *out) {
    const uint16_t *initout = out;
    if (lenA == 0 || lenB == 0) return 0;
    const uint16_t *endA = A + lenA;
    const uint16_t *endB = B + lenB;

    while (1) {
        while (*A < *B) {
        SKIP_FIRST_COMPARE:
            if (++A == endA) return (int32_t)(out - initout);
        }
        while (*A > *B) {
            if (++B == endB) return (int32_t)(out - initout);
        }
        if (*A == *B) {
            *out++ = *A;
            if (++A == endA || ++B == endB) return (int32_t)(out - initout);
        } else {
            goto SKIP_FIRST_COMPARE;
        }
    }
    return (int32_t)(out - initout);  // NOTREACHED
}

static int32_t intersect_uint16_cardinality(const uint16_t *A, const size_t lenA,
                                     const uint16_t *B, const size_t lenB) {
    int32_t answer = 0;
    if (lenA == 0 || lenB == 0) return 0;
    const uint16_t *endA = A + lenA;
    const uint16_t *endB = B + lenB;

    while (1) {
        while (*A < *B) {
        SKIP_FIRST_COMPARE:
            if (++A == endA) return answer;
        }
        while (*A > *B) {
            if (++B == endB) return answer;
        }
        if (*A == *B) {
            ++answer;
            if (++A == endA || ++B == endB) return answer;
        } else {
            goto SKIP_FIRST_COMPARE;
        }
    }
    return answer;  // NOTREACHED
}


static bool intersect_uint16_nonempty(const uint16_t *A, const size_t lenA,
                         const uint16_t *B, const size_t lenB) {
    if (lenA == 0 || lenB == 0) return 0;
    const uint16_t *endA = A + lenA;
    const uint16_t *endB = B + lenB;

    while (1) {
        while (*A < *B) {
        SKIP_FIRST_COMPARE:
            if (++A == endA) return false;
        }
        while (*A > *B) {
            if (++B == endB) return false;
        }
        if (*A == *B) {
            return true;
        } else {
            goto SKIP_FIRST_COMPARE;
        }
    }
    return false;  // NOTREACHED
}



/**
 * Generic intersection function.
 */
static size_t intersection_uint32(const uint32_t *A, const size_t lenA,
                           const uint32_t *B, const size_t lenB,
                           uint32_t *out) {
    const uint32_t *initout = out;
    if (lenA == 0 || lenB == 0) return 0;
    const uint32_t *endA = A + lenA;
    const uint32_t *endB = B + lenB;

    while (1) {
        while (*A < *B) {
        SKIP_FIRST_COMPARE:
            if (++A == endA) return (out - initout);
        }
        while (*A > *B) {
            if (++B == endB) return (out - initout);
        }
        if (*A == *B) {
            *out++ = *A;
            if (++A == endA || ++B == endB) return (out - initout);
        } else {
            goto SKIP_FIRST_COMPARE;
        }
    }
    return (out - initout);  // NOTREACHED
}

static size_t intersection_uint32_card(const uint32_t *A, const size_t lenA,
                                const uint32_t *B, const size_t lenB) {
    if (lenA == 0 || lenB == 0) return 0;
    size_t card = 0;
    const uint32_t *endA = A + lenA;
    const uint32_t *endB = B + lenB;

    while (1) {
        while (*A < *B) {
        SKIP_FIRST_COMPARE:
            if (++A == endA) return card;
        }
        while (*A > *B) {
            if (++B == endB) return card;
        }
        if (*A == *B) {
            card++;
            if (++A == endA || ++B == endB) return card;
        } else {
            goto SKIP_FIRST_COMPARE;
        }
    }
    return card;  // NOTREACHED
}

// can one vectorize the computation of the union? (Update: Yes! See
// union_vector16).

static size_t union_uint16(const uint16_t *set_1, size_t size_1, const uint16_t *set_2,
                    size_t size_2, uint16_t *buffer) {
    size_t pos = 0, idx_1 = 0, idx_2 = 0;

    if (0 == size_2) {
        memmove(buffer, set_1, size_1 * sizeof(uint16_t));
        return size_1;
    }
    if (0 == size_1) {
        memmove(buffer, set_2, size_2 * sizeof(uint16_t));
        return size_2;
    }

    uint16_t val_1 = set_1[idx_1], val_2 = set_2[idx_2];

    while (true) {
        if (val_1 < val_2) {
            buffer[pos++] = val_1;
            ++idx_1;
            if (idx_1 >= size_1) break;
            val_1 = set_1[idx_1];
        } else if (val_2 < val_1) {
            buffer[pos++] = val_2;
            ++idx_2;
            if (idx_2 >= size_2) break;
            val_2 = set_2[idx_2];
        } else {
            buffer[pos++] = val_1;
            ++idx_1;
            ++idx_2;
            if (idx_1 >= size_1 || idx_2 >= size_2) break;
            val_1 = set_1[idx_1];
            val_2 = set_2[idx_2];
        }
    }

    if (idx_1 < size_1) {
        const size_t n_elems = size_1 - idx_1;
        memmove(buffer + pos, set_1 + idx_1, n_elems * sizeof(uint16_t));
        pos += n_elems;
    } else if (idx_2 < size_2) {
        const size_t n_elems = size_2 - idx_2;
        memmove(buffer + pos, set_2 + idx_2, n_elems * sizeof(uint16_t));
        pos += n_elems;
    }

    return pos;
}

static int difference_uint16(const uint16_t *a1, int length1, const uint16_t *a2,
                      int length2, uint16_t *a_out) {
    int out_card = 0;
    int k1 = 0, k2 = 0;
    if (length1 == 0) return 0;
    if (length2 == 0) {
        if (a1 != a_out) memcpy(a_out, a1, sizeof(uint16_t) * length1);
        return length1;
    }
    uint16_t s1 = a1[k1];
    uint16_t s2 = a2[k2];
    while (true) {
        if (s1 < s2) {
            a_out[out_card++] = s1;
            ++k1;
            if (k1 >= length1) {
                break;
            }
            s1 = a1[k1];
        } else if (s1 == s2) {
            ++k1;
            ++k2;
            if (k1 >= length1) {
                break;
            }
            if (k2 >= length2) {
                memmove(a_out + out_card, a1 + k1,
                        sizeof(uint16_t) * (length1 - k1));
                return out_card + length1 - k1;
            }
            s1 = a1[k1];
            s2 = a2[k2];
        } else {  // if (val1>val2)
            ++k2;
            if (k2 >= length2) {
                memmove(a_out + out_card, a1 + k1,
                        sizeof(uint16_t) * (length1 - k1));
                return out_card + length1 - k1;
            }
            s2 = a2[k2];
        }
    }
    return out_card;
}

static int32_t xor_uint16(const uint16_t *array_1, int32_t card_1,
                   const uint16_t *array_2, int32_t card_2, uint16_t *out) {
    int32_t pos1 = 0, pos2 = 0, pos_out = 0;
    while (pos1 < card_1 && pos2 < card_2) {
        const uint16_t v1 = array_1[pos1];
        const uint16_t v2 = array_2[pos2];
        if (v1 == v2) {
            ++pos1;
            ++pos2;
            continue;
        }
        if (v1 < v2) {
            out[pos_out++] = v1;
            ++pos1;
        } else {
            out[pos_out++] = v2;
            ++pos2;
        }
    }
    if (pos1 < card_1) {
        const size_t n_elems = card_1 - pos1;
        memcpy(out + pos_out, array_1 + pos1, n_elems * sizeof(uint16_t));
        pos_out += (int32_t)n_elems;
    } else if (pos2 < card_2) {
        const size_t n_elems = card_2 - pos2;
        memcpy(out + pos_out, array_2 + pos2, n_elems * sizeof(uint16_t));
        pos_out += (int32_t)n_elems;
    }
    return pos_out;
}

#ifdef CROARING_IS_X64

/***
 * start of the SIMD 16-bit union code
 *
 */
CROARING_TARGET_AVX2

// Assuming that vInput1 and vInput2 are sorted, produces a sorted output going
// from vecMin all the way to vecMax
// developed originally for merge sort using SIMD instructions.
// Standard merge. See, e.g., Inoue and Taura, SIMD- and Cache-Friendly
// Algorithm for Sorting an Array of Structures
static inline void sse_merge(const __m128i *vInput1,
                             const __m128i *vInput2,              // input 1 & 2
                             __m128i *vecMin, __m128i *vecMax) {  // output
    __m128i vecTmp;
    vecTmp = _mm_min_epu16(*vInput1, *vInput2);
    *vecMax = _mm_max_epu16(*vInput1, *vInput2);
    vecTmp = _mm_alignr_epi8(vecTmp, vecTmp, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    vecTmp = _mm_alignr_epi8(*vecMin, *vecMin, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    vecTmp = _mm_alignr_epi8(*vecMin, *vecMin, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    vecTmp = _mm_alignr_epi8(*vecMin, *vecMin, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    vecTmp = _mm_alignr_epi8(*vecMin, *vecMin, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    vecTmp = _mm_alignr_epi8(*vecMin, *vecMin, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    vecTmp = _mm_alignr_epi8(*vecMin, *vecMin, 2);
    *vecMin = _mm_min_epu16(vecTmp, *vecMax);
    *vecMax = _mm_max_epu16(vecTmp, *vecMax);
    *vecMin = _mm_alignr_epi8(*vecMin, *vecMin, 2);
}
CROARING_UNTARGET_REGION
// used by store_unique, generated by simdunion.py
static uint8_t uniqshuf[] = {
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,
    0xc,  0xd,  0xe,  0xf,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,
    0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0x8,  0x9,
    0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x8,  0x9,
    0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x8,  0x9,
    0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
    0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0xa,  0xb,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0xa,  0xb,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0xa,  0xb,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0xa,  0xb,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xa,  0xb,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,
    0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,
    0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x8,  0x9,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x8,  0x9,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x8,  0x9,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x6,  0x7,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x6,  0x7,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x6,  0x7,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0xc,  0xd,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0xc,  0xd,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xc,  0xd,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
    0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0x8,  0x9,
    0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x8,  0x9,  0xa,  0xb,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x8,  0x9,
    0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x8,  0x9,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0xa,  0xb,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,
    0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,  0xa,  0xb,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,
    0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x6,  0x7,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0xa,  0xb,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0xa,  0xb,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xa,  0xb,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x6,  0x7,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0x8,  0x9,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,
    0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x6,  0x7,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x8,  0x9,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x8,  0x9,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x8,  0x9,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x8,  0x9,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x6,  0x7,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x6,  0x7,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x6,  0x7,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0xe,  0xf,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0xe,  0xf,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xe,  0xf,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,
    0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x8,  0x9,
    0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x8,  0x9,  0xa,  0xb,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x8,  0x9,  0xa,  0xb,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xa,  0xb,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0xa,  0xb,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,
    0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0xa,  0xb,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0xa,  0xb,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0xa,  0xb,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xa,  0xb,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
    0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,  0x8,  0x9,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0x8,  0x9,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x8,  0x9,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x8,  0x9,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x8,  0x9,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x6,  0x7,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,  0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x6,  0x7,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0xc,  0xd,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0xc,  0xd,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xc,  0xd,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,
    0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0x8,  0x9,
    0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,
    0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x8,  0x9,  0xa,  0xb,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x8,  0x9,
    0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x8,  0x9,
    0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x8,  0x9,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,
    0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x6,  0x7,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,  0xa,  0xb,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x6,  0x7,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x6,  0x7,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,  0xa,  0xb,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0xa,  0xb,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0xa,  0xb,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0xa,  0xb,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0xa,  0xb,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xa,  0xb,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0x6,  0x7,  0x8,  0x9,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x6,  0x7,
    0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,  0x8,  0x9,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x6,  0x7,
    0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x6,  0x7,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x8,  0x9,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,
    0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x4,  0x5,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x8,  0x9,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x8,  0x9,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x4,  0x5,  0x6,  0x7,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,
    0x6,  0x7,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x4,  0x5,  0x6,  0x7,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,  0x6,  0x7,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0x6,  0x7,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x6,  0x7,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x6,  0x7,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x2,  0x3,
    0x4,  0x5,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x2,  0x3,  0x4,  0x5,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0x4,  0x5,  0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x4,  0x5,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x0,  0x1,  0x2,  0x3,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x2,  0x3,  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x0,  0x1,  0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF};
CROARING_TARGET_AVX2
// write vector new, while omitting repeated values assuming that previously
// written vector was "old"
static inline int store_unique(__m128i old, __m128i newval, uint16_t *output) {
    __m128i vecTmp = _mm_alignr_epi8(newval, old, 16 - 2);
    // lots of high latency instructions follow (optimize?)
    int M = _mm_movemask_epi8(
        _mm_packs_epi16(_mm_cmpeq_epi16(vecTmp, newval), _mm_setzero_si128()));
    int numberofnewvalues = 8 - _mm_popcnt_u32(M);
    __m128i key = _mm_lddqu_si128((const __m128i *)uniqshuf + M);
    __m128i val = _mm_shuffle_epi8(newval, key);
    _mm_storeu_si128((__m128i *)output, val);
    return numberofnewvalues;
}
CROARING_UNTARGET_REGION

// working in-place, this function overwrites the repeated values
// could be avoided?
static inline uint32_t unique(uint16_t *out, uint32_t len) {
    uint32_t pos = 1;
    uint32_t i; for (i = 1; i < len; ++i) {
        if (out[i] != out[i - 1]) {
            out[pos++] = out[i];
        }
    }
    return pos;
}

// use with qsort, could be avoided
static int uint16_compare(const void *a, const void *b) {
    return (*(uint16_t *)a - *(uint16_t *)b);
}

CROARING_TARGET_AVX2
// a one-pass SSE union algorithm
// This function may not be safe if array1 == output or array2 == output.
static uint32_t union_vector16(const uint16_t *__restrict__ array1, uint32_t length1,
                        const uint16_t *__restrict__ array2, uint32_t length2,
                        uint16_t *__restrict__ output) {
    if ((length1 < 8) || (length2 < 8)) {
        return (uint32_t)union_uint16(array1, length1, array2, length2, output);
    }
    __m128i vA, vB, V, vecMin, vecMax;
    __m128i laststore;
    uint16_t *initoutput = output;
    uint32_t len1 = length1 / 8;
    uint32_t len2 = length2 / 8;
    uint32_t pos1 = 0;
    uint32_t pos2 = 0;
    // we start the machine
    vA = _mm_lddqu_si128((const __m128i *)array1 + pos1);
    pos1++;
    vB = _mm_lddqu_si128((const __m128i *)array2 + pos2);
    pos2++;
    sse_merge(&vA, &vB, &vecMin, &vecMax);
    laststore = _mm_set1_epi16(-1);
    output += store_unique(laststore, vecMin, output);
    laststore = vecMin;
    if ((pos1 < len1) && (pos2 < len2)) {
        uint16_t curA, curB;
        curA = array1[8 * pos1];
        curB = array2[8 * pos2];
        while (true) {
            if (curA <= curB) {
                V = _mm_lddqu_si128((const __m128i *)array1 + pos1);
                pos1++;
                if (pos1 < len1) {
                    curA = array1[8 * pos1];
                } else {
                    break;
                }
            } else {
                V = _mm_lddqu_si128((const __m128i *)array2 + pos2);
                pos2++;
                if (pos2 < len2) {
                    curB = array2[8 * pos2];
                } else {
                    break;
                }
            }
            sse_merge(&V, &vecMax, &vecMin, &vecMax);
            output += store_unique(laststore, vecMin, output);
            laststore = vecMin;
        }
        sse_merge(&V, &vecMax, &vecMin, &vecMax);
        output += store_unique(laststore, vecMin, output);
        laststore = vecMin;
    }
    // we finish the rest off using a scalar algorithm
    // could be improved?
    //
    // copy the small end on a tmp buffer
    uint32_t len = (uint32_t)(output - initoutput);
    uint16_t buffer[16];
    uint32_t leftoversize = store_unique(laststore, vecMax, buffer);
    if (pos1 == len1) {
        memcpy(buffer + leftoversize, array1 + 8 * pos1,
               (length1 - 8 * len1) * sizeof(uint16_t));
        leftoversize += length1 - 8 * len1;
        qsort(buffer, leftoversize, sizeof(uint16_t), uint16_compare);

        leftoversize = unique(buffer, leftoversize);
        len += (uint32_t)union_uint16(buffer, leftoversize, array2 + 8 * pos2,
                                      length2 - 8 * pos2, output);
    } else {
        memcpy(buffer + leftoversize, array2 + 8 * pos2,
               (length2 - 8 * len2) * sizeof(uint16_t));
        leftoversize += length2 - 8 * len2;
        qsort(buffer, leftoversize, sizeof(uint16_t), uint16_compare);
        leftoversize = unique(buffer, leftoversize);
        len += (uint32_t)union_uint16(buffer, leftoversize, array1 + 8 * pos1,
                                      length1 - 8 * pos1, output);
    }
    return len;
}
CROARING_UNTARGET_REGION

/**
 * End of the SIMD 16-bit union code
 *
 */

/**
 * Start of SIMD 16-bit XOR code
 */

CROARING_TARGET_AVX2
// write vector new, while omitting repeated values assuming that previously
// written vector was "old"
static inline int store_unique_xor(__m128i old, __m128i newval,
                                   uint16_t *output) {
    __m128i vecTmp1 = _mm_alignr_epi8(newval, old, 16 - 4);
    __m128i vecTmp2 = _mm_alignr_epi8(newval, old, 16 - 2);
    __m128i equalleft = _mm_cmpeq_epi16(vecTmp2, vecTmp1);
    __m128i equalright = _mm_cmpeq_epi16(vecTmp2, newval);
    __m128i equalleftoright = _mm_or_si128(equalleft, equalright);
    int M = _mm_movemask_epi8(
        _mm_packs_epi16(equalleftoright, _mm_setzero_si128()));
    int numberofnewvalues = 8 - _mm_popcnt_u32(M);
    __m128i key = _mm_lddqu_si128((const __m128i *)uniqshuf + M);
    __m128i val = _mm_shuffle_epi8(vecTmp2, key);
    _mm_storeu_si128((__m128i *)output, val);
    return numberofnewvalues;
}
CROARING_UNTARGET_REGION

// working in-place, this function overwrites the repeated values
// could be avoided? Warning: assumes len > 0
static inline uint32_t unique_xor(uint16_t *out, uint32_t len) {
    uint32_t pos = 1;
    uint32_t i; for (i = 1; i < len; ++i) {
        if (out[i] != out[i - 1]) {
            out[pos++] = out[i];
        } else
            pos--;  // if it is identical to previous, delete it
    }
    return pos;
}
CROARING_TARGET_AVX2
// a one-pass SSE xor algorithm
static uint32_t xor_vector16(const uint16_t *__restrict__ array1, uint32_t length1,
                      const uint16_t *__restrict__ array2, uint32_t length2,
                      uint16_t *__restrict__ output) {
    if ((length1 < 8) || (length2 < 8)) {
        return xor_uint16(array1, length1, array2, length2, output);
    }
    __m128i vA, vB, V, vecMin, vecMax;
    __m128i laststore;
    uint16_t *initoutput = output;
    uint32_t len1 = length1 / 8;
    uint32_t len2 = length2 / 8;
    uint32_t pos1 = 0;
    uint32_t pos2 = 0;
    // we start the machine
    vA = _mm_lddqu_si128((const __m128i *)array1 + pos1);
    pos1++;
    vB = _mm_lddqu_si128((const __m128i *)array2 + pos2);
    pos2++;
    sse_merge(&vA, &vB, &vecMin, &vecMax);
    laststore = _mm_set1_epi16(-1);
    uint16_t buffer[17];
    output += store_unique_xor(laststore, vecMin, output);

    laststore = vecMin;
    if ((pos1 < len1) && (pos2 < len2)) {
        uint16_t curA, curB;
        curA = array1[8 * pos1];
        curB = array2[8 * pos2];
        while (true) {
            if (curA <= curB) {
                V = _mm_lddqu_si128((const __m128i *)array1 + pos1);
                pos1++;
                if (pos1 < len1) {
                    curA = array1[8 * pos1];
                } else {
                    break;
                }
            } else {
                V = _mm_lddqu_si128((const __m128i *)array2 + pos2);
                pos2++;
                if (pos2 < len2) {
                    curB = array2[8 * pos2];
                } else {
                    break;
                }
            }
            sse_merge(&V, &vecMax, &vecMin, &vecMax);
            // conditionally stores the last value of laststore as well as all
            // but the
            // last value of vecMin
            output += store_unique_xor(laststore, vecMin, output);
            laststore = vecMin;
        }
        sse_merge(&V, &vecMax, &vecMin, &vecMax);
        // conditionally stores the last value of laststore as well as all but
        // the
        // last value of vecMin
        output += store_unique_xor(laststore, vecMin, output);
        laststore = vecMin;
    }
    uint32_t len = (uint32_t)(output - initoutput);

    // we finish the rest off using a scalar algorithm
    // could be improved?
    // conditionally stores the last value of laststore as well as all but the
    // last value of vecMax,
    // we store to "buffer"
    int leftoversize = store_unique_xor(laststore, vecMax, buffer);
    uint16_t vec7 = _mm_extract_epi16(vecMax, 7);
    uint16_t vec6 = _mm_extract_epi16(vecMax, 6);
    if (vec7 != vec6) buffer[leftoversize++] = vec7;
    if (pos1 == len1) {
        memcpy(buffer + leftoversize, array1 + 8 * pos1,
               (length1 - 8 * len1) * sizeof(uint16_t));
        leftoversize += length1 - 8 * len1;
        if (leftoversize == 0) {  // trivial case
            memcpy(output, array2 + 8 * pos2,
                   (length2 - 8 * pos2) * sizeof(uint16_t));
            len += (length2 - 8 * pos2);
        } else {
            qsort(buffer, leftoversize, sizeof(uint16_t), uint16_compare);
            leftoversize = unique_xor(buffer, leftoversize);
            len += xor_uint16(buffer, leftoversize, array2 + 8 * pos2,
                              length2 - 8 * pos2, output);
        }
    } else {
        memcpy(buffer + leftoversize, array2 + 8 * pos2,
               (length2 - 8 * len2) * sizeof(uint16_t));
        leftoversize += length2 - 8 * len2;
        if (leftoversize == 0) {  // trivial case
            memcpy(output, array1 + 8 * pos1,
                   (length1 - 8 * pos1) * sizeof(uint16_t));
            len += (length1 - 8 * pos1);
        } else {
            qsort(buffer, leftoversize, sizeof(uint16_t), uint16_compare);
            leftoversize = unique_xor(buffer, leftoversize);
            len += xor_uint16(buffer, leftoversize, array1 + 8 * pos1,
                              length1 - 8 * pos1, output);
        }
    }
    return len;
}
CROARING_UNTARGET_REGION
/**
 * End of SIMD 16-bit XOR code
 */

#endif  // CROARING_IS_X64

static size_t union_uint32(const uint32_t *set_1, size_t size_1, const uint32_t *set_2,
                    size_t size_2, uint32_t *buffer) {
    size_t pos = 0, idx_1 = 0, idx_2 = 0;

    if (0 == size_2) {
        memmove(buffer, set_1, size_1 * sizeof(uint32_t));
        return size_1;
    }
    if (0 == size_1) {
        memmove(buffer, set_2, size_2 * sizeof(uint32_t));
        return size_2;
    }

    uint32_t val_1 = set_1[idx_1], val_2 = set_2[idx_2];

    while (true) {
        if (val_1 < val_2) {
            buffer[pos++] = val_1;
            ++idx_1;
            if (idx_1 >= size_1) break;
            val_1 = set_1[idx_1];
        } else if (val_2 < val_1) {
            buffer[pos++] = val_2;
            ++idx_2;
            if (idx_2 >= size_2) break;
            val_2 = set_2[idx_2];
        } else {
            buffer[pos++] = val_1;
            ++idx_1;
            ++idx_2;
            if (idx_1 >= size_1 || idx_2 >= size_2) break;
            val_1 = set_1[idx_1];
            val_2 = set_2[idx_2];
        }
    }

    if (idx_1 < size_1) {
        const size_t n_elems = size_1 - idx_1;
        memmove(buffer + pos, set_1 + idx_1, n_elems * sizeof(uint32_t));
        pos += n_elems;
    } else if (idx_2 < size_2) {
        const size_t n_elems = size_2 - idx_2;
        memmove(buffer + pos, set_2 + idx_2, n_elems * sizeof(uint32_t));
        pos += n_elems;
    }

    return pos;
}

static size_t union_uint32_card(const uint32_t *set_1, size_t size_1,
                         const uint32_t *set_2, size_t size_2) {
    size_t pos = 0, idx_1 = 0, idx_2 = 0;

    if (0 == size_2) {
        return size_1;
    }
    if (0 == size_1) {
        return size_2;
    }

    uint32_t val_1 = set_1[idx_1], val_2 = set_2[idx_2];

    while (true) {
        if (val_1 < val_2) {
            ++idx_1;
            ++pos;
            if (idx_1 >= size_1) break;
            val_1 = set_1[idx_1];
        } else if (val_2 < val_1) {
            ++idx_2;
            ++pos;
            if (idx_2 >= size_2) break;
            val_2 = set_2[idx_2];
        } else {
            ++idx_1;
            ++idx_2;
            ++pos;
            if (idx_1 >= size_1 || idx_2 >= size_2) break;
            val_1 = set_1[idx_1];
            val_2 = set_2[idx_2];
        }
    }

    if (idx_1 < size_1) {
        const size_t n_elems = size_1 - idx_1;
        pos += n_elems;
    } else if (idx_2 < size_2) {
        const size_t n_elems = size_2 - idx_2;
        pos += n_elems;
    }
    return pos;
}



static size_t fast_union_uint16(const uint16_t *set_1, size_t size_1, const uint16_t *set_2,
                    size_t size_2, uint16_t *buffer) {
#ifdef CROARING_IS_X64
    if( croaring_avx2() ) {
        // compute union with smallest array first
      if (size_1 < size_2) {
        return union_vector16(set_1, (uint32_t)size_1,
                                          set_2, (uint32_t)size_2, buffer);
      } else {
        return union_vector16(set_2, (uint32_t)size_2,
                                          set_1, (uint32_t)size_1, buffer);
      }
    } else {
       // compute union with smallest array first
      if (size_1 < size_2) {
        return union_uint16(
            set_1, size_1, set_2, size_2, buffer);
      } else {
        return union_uint16(
            set_2, size_2, set_1, size_1, buffer);
      }
    }
#else
    // compute union with smallest array first
    if (size_1 < size_2) {
        return union_uint16(
            set_1, size_1, set_2, size_2, buffer);
    } else {
        return union_uint16(
            set_2, size_2, set_1, size_1, buffer);
    }
#endif
}
#ifdef CROARING_IS_X64
CROARING_TARGET_AVX2
static inline bool _avx2_memequals(const void *s1, const void *s2, size_t n) {
    const uint8_t *ptr1 = (const uint8_t *)s1;
    const uint8_t *ptr2 = (const uint8_t *)s2;
    const uint8_t *end1 = ptr1 + n;
    const uint8_t *end8 = ptr1 + n/8*8;
    const uint8_t *end32 = ptr1 + n/32*32;

    while (ptr1 < end32) {
        __m256i r1 = _mm256_loadu_si256((const __m256i*)ptr1);
        __m256i r2 = _mm256_loadu_si256((const __m256i*)ptr2);
        int mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(r1, r2));
        if ((uint32_t)mask != UINT32_MAX) {
            return false;
        }
        ptr1 += 32;
        ptr2 += 32;
    }

    while (ptr1 < end8) {
        uint64_t v1 = *((const uint64_t*)ptr1);
        uint64_t v2 = *((const uint64_t*)ptr2);
        if (v1 != v2) {
            return false;
        }
        ptr1 += 8;
        ptr2 += 8;
    }

    while (ptr1 < end1) {
        if (*ptr1 != *ptr2) {
            return false;
        }
        ptr1++;
        ptr2++;
    }

    return true;
}
CROARING_UNTARGET_REGION
#endif

static bool memequals(const void *s1, const void *s2, size_t n) {
    if (n == 0) {
        return true;
    }
#ifdef CROARING_IS_X64
    if( croaring_avx2() ) {
      return _avx2_memequals(s1, s2, n);
    } else {
      return memcmp(s1, s2, n) == 0;
    }
#else
    return memcmp(s1, s2, n) == 0;
#endif
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/array_util.c */
/* begin file src/containers/array.c */
/*
 * array.c
 *
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

extern inline uint16_t array_container_minimum(const array_container_t *arr);
extern inline uint16_t array_container_maximum(const array_container_t *arr);
extern inline int array_container_index_equalorlarger(const array_container_t *arr, uint16_t x);

extern inline int array_container_rank(const array_container_t *arr,
                                       uint16_t x);
extern inline bool array_container_contains(const array_container_t *arr,
                                            uint16_t pos);
extern inline int array_container_cardinality(const array_container_t *array);
extern inline bool array_container_nonzero_cardinality(const array_container_t *array);
extern inline void array_container_clear(array_container_t *array);
extern inline int32_t array_container_serialized_size_in_bytes(int32_t card);
extern inline bool array_container_empty(const array_container_t *array);
extern inline bool array_container_full(const array_container_t *array);

/* Create a new array with capacity size. Return NULL in case of failure. */
static array_container_t *array_container_create_given_capacity(int32_t size) {
    array_container_t *container;

    if ((container = (array_container_t *)ndpi_malloc(sizeof(array_container_t))) ==
        NULL) {
        return NULL;
    }

    if( size <= 0 ) { // we don't want to rely on malloc(0)
        container->array = NULL;
    } else if ((container->array = (uint16_t *)ndpi_malloc(sizeof(uint16_t) * size)) ==
        NULL) {
        ndpi_free(container);
        return NULL;
    }

    container->capacity = size;
    container->cardinality = 0;

    return container;
}

/* Create a new array. Return NULL in case of failure. */
static array_container_t *array_container_create() {
    return array_container_create_given_capacity(ARRAY_DEFAULT_INIT_SIZE);
}

/* Create a new array containing all values in [min,max). */
static array_container_t * array_container_create_range(uint32_t min, uint32_t max) {
    array_container_t * answer = array_container_create_given_capacity(max - min + 1);
    if(answer == NULL) return answer;
    answer->cardinality = 0;
    uint32_t k; for(k = min; k < max; k++) {
      answer->array[answer->cardinality++] = k;
    }
    return answer;
}

/* Duplicate container */
static array_container_t *array_container_clone(const array_container_t *src) {
    array_container_t *newcontainer =
        array_container_create_given_capacity(src->capacity);
    if (newcontainer == NULL) return NULL;

    newcontainer->cardinality = src->cardinality;

    memcpy(newcontainer->array, src->array,
           src->cardinality * sizeof(uint16_t));

    return newcontainer;
}

static int array_container_shrink_to_fit(array_container_t *src) {
    if (src->cardinality == src->capacity) return 0;  // nothing to do
    int old_capacity = src->capacity;
    int savings = src->capacity - src->cardinality;
    src->capacity = src->cardinality;
    if( src->capacity == 0) { // we do not want to rely on realloc for zero allocs
      ndpi_free(src->array);
      src->array = NULL;
    } else {
      uint16_t *oldarray = src->array;
      src->array =
        (uint16_t *)ndpi_realloc(oldarray, old_capacity * sizeof(uint16_t), src->capacity * sizeof(uint16_t));
      if (src->array == NULL) ndpi_free(oldarray);  // should never happen?
    }
    return savings;
}

/* Free memory. */
static void array_container_free(array_container_t *arr) {
    if(arr->array != NULL) {// Jon Strabala reports that some tools complain otherwise
      ndpi_free(arr->array);
      arr->array = NULL; // pedantic
    }
    ndpi_free(arr);
}

static inline int32_t grow_capacity(int32_t capacity) {
    return (capacity <= 0) ? ARRAY_DEFAULT_INIT_SIZE
                           : capacity < 64 ? capacity * 2
                                           : capacity < 1024 ? capacity * 3 / 2
                                                             : capacity * 5 / 4;
}

static inline int32_t clamp(int32_t val, int32_t min, int32_t max) {
    return ((val < min) ? min : (val > max) ? max : val);
}

static void array_container_grow(array_container_t *container, int32_t min,
                          bool preserve) {

    int32_t max = (min <= DEFAULT_MAX_SIZE ? DEFAULT_MAX_SIZE : 65536);
    int32_t new_capacity = clamp(grow_capacity(container->capacity), min, max);
    int32_t old_capacity = container->capacity;

    container->capacity = new_capacity;
    uint16_t *array = container->array;

    if (preserve) {
        container->array =
            (uint16_t *)ndpi_realloc(array, old_capacity * sizeof(uint16_t), new_capacity * sizeof(uint16_t));
        if (container->array == NULL) ndpi_free(array);
    } else {
        // Jon Strabala reports that some tools complain otherwise
        if (array != NULL) {
          ndpi_free(array);
        }
        container->array = (uint16_t *)ndpi_malloc(new_capacity * sizeof(uint16_t));
    }

    //  handle the case where realloc fails
    if (container->array == NULL) {
      fprintf(stderr, "could not allocate memory\n");
    }
    assert(container->array != NULL);
}

/* Copy one container into another. We assume that they are distinct. */
static void array_container_copy(const array_container_t *src,
                          array_container_t *dst) {
    const int32_t cardinality = src->cardinality;
    if (cardinality > dst->capacity) {
        array_container_grow(dst, cardinality, false);
    }

    dst->cardinality = cardinality;
    memcpy(dst->array, src->array, cardinality * sizeof(uint16_t));
}

static void array_container_add_from_range(array_container_t *arr, uint32_t min,
                                    uint32_t max, uint16_t step) {
    uint32_t value; for (value = min; value < max; value += step) {
        array_container_append(arr, value);
    }
}

/* Computes the union of array1 and array2 and write the result to arrayout.
 * It is assumed that arrayout is distinct from both array1 and array2.
 */
static void array_container_union(const array_container_t *array_1,
                           const array_container_t *array_2,
                           array_container_t *out) {
    const int32_t card_1 = array_1->cardinality, card_2 = array_2->cardinality;
    const int32_t max_cardinality = card_1 + card_2;

    if (out->capacity < max_cardinality) {
      array_container_grow(out, max_cardinality, false);
    }
    out->cardinality = (int32_t)fast_union_uint16(array_1->array, card_1,
                                      array_2->array, card_2, out->array);

}

/* Computes the  difference of array1 and array2 and write the result
 * to array out.
 * Array out does not need to be distinct from array_1
 */
static void array_container_andnot(const array_container_t *array_1,
                            const array_container_t *array_2,
                            array_container_t *out) {
    if (out->capacity < array_1->cardinality)
        array_container_grow(out, array_1->cardinality, false);
#ifdef CROARING_IS_X64
    if(( croaring_avx2() ) && (out != array_1) && (out != array_2)) {
      out->cardinality =
          difference_vector16(array_1->array, array_1->cardinality,
                            array_2->array, array_2->cardinality, out->array);
     } else {
      out->cardinality =
        difference_uint16(array_1->array, array_1->cardinality, array_2->array,
                          array_2->cardinality, out->array);
     }
#else
    out->cardinality =
        difference_uint16(array_1->array, array_1->cardinality, array_2->array,
                          array_2->cardinality, out->array);
#endif
}

/* Computes the symmetric difference of array1 and array2 and write the
 * result
 * to arrayout.
 * It is assumed that arrayout is distinct from both array1 and array2.
 */
static void array_container_xor(const array_container_t *array_1,
                         const array_container_t *array_2,
                         array_container_t *out) {
    const int32_t card_1 = array_1->cardinality, card_2 = array_2->cardinality;
    const int32_t max_cardinality = card_1 + card_2;
    if (out->capacity < max_cardinality) {
        array_container_grow(out, max_cardinality, false);
    }

#ifdef CROARING_IS_X64
    if( croaring_avx2() ) {
      out->cardinality =
        xor_vector16(array_1->array, array_1->cardinality, array_2->array,
                     array_2->cardinality, out->array);
    } else {
      out->cardinality =
        xor_uint16(array_1->array, array_1->cardinality, array_2->array,
                   array_2->cardinality, out->array);
    }
#else
    out->cardinality =
        xor_uint16(array_1->array, array_1->cardinality, array_2->array,
                   array_2->cardinality, out->array);
#endif
}

static inline int32_t minimum_int32(int32_t a, int32_t b) {
    return (a < b) ? a : b;
}

/* computes the intersection of array1 and array2 and write the result to
 * arrayout.
 * It is assumed that arrayout is distinct from both array1 and array2.
 * */
static void array_container_intersection(const array_container_t *array1,
                                  const array_container_t *array2,
                                  array_container_t *out) {
    int32_t card_1 = array1->cardinality, card_2 = array2->cardinality,
            min_card = minimum_int32(card_1, card_2);
    const int threshold = 64;  // subject to tuning
#ifdef CROARING_IS_X64
    if (out->capacity < min_card) {
      array_container_grow(out, min_card + sizeof(__m128i) / sizeof(uint16_t),
        false);
    }
#else
    if (out->capacity < min_card) {
      array_container_grow(out, min_card, false);
    }
#endif

    if (card_1 * threshold < card_2) {
        out->cardinality = intersect_skewed_uint16(
            array1->array, card_1, array2->array, card_2, out->array);
    } else if (card_2 * threshold < card_1) {
        out->cardinality = intersect_skewed_uint16(
            array2->array, card_2, array1->array, card_1, out->array);
    } else {
#ifdef CROARING_IS_X64
       if( croaring_avx2() ) {
        out->cardinality = intersect_vector16(
            array1->array, card_1, array2->array, card_2, out->array);
       } else {
        out->cardinality = intersect_uint16(array1->array, card_1,
                                            array2->array, card_2, out->array);
       }
#else
        out->cardinality = intersect_uint16(array1->array, card_1,
                                            array2->array, card_2, out->array);
#endif
    }
}

/* computes the size of the intersection of array1 and array2
 * */
static int array_container_intersection_cardinality(const array_container_t *array1,
                                             const array_container_t *array2) {
    int32_t card_1 = array1->cardinality, card_2 = array2->cardinality;
    const int threshold = 64;  // subject to tuning
    if (card_1 * threshold < card_2) {
        return intersect_skewed_uint16_cardinality(array1->array, card_1,
                                                   array2->array, card_2);
    } else if (card_2 * threshold < card_1) {
        return intersect_skewed_uint16_cardinality(array2->array, card_2,
                                                   array1->array, card_1);
    } else {
#ifdef CROARING_IS_X64
    if( croaring_avx2() ) {
        return intersect_vector16_cardinality(array1->array, card_1,
                                              array2->array, card_2);
    } else {
        return intersect_uint16_cardinality(array1->array, card_1,
                                            array2->array, card_2);
    }
#else
        return intersect_uint16_cardinality(array1->array, card_1,
                                            array2->array, card_2);
#endif
    }
}

static bool array_container_intersect(const array_container_t *array1,
                                  const array_container_t *array2) {
    int32_t card_1 = array1->cardinality, card_2 = array2->cardinality;
    const int threshold = 64;  // subject to tuning
    if (card_1 * threshold < card_2) {
        return intersect_skewed_uint16_nonempty(
            array1->array, card_1, array2->array, card_2);
    } else if (card_2 * threshold < card_1) {
    	return intersect_skewed_uint16_nonempty(
            array2->array, card_2, array1->array, card_1);
    } else {
    	// we do not bother vectorizing
        return intersect_uint16_nonempty(array1->array, card_1,
                                            array2->array, card_2);
    }
}

/* computes the intersection of array1 and array2 and write the result to
 * array1.
 * */
static void array_container_intersection_inplace(array_container_t *src_1,
                                          const array_container_t *src_2) {
    // todo: can any of this be vectorized?
    int32_t card_1 = src_1->cardinality, card_2 = src_2->cardinality;
    const int threshold = 64;  // subject to tuning
    if (card_1 * threshold < card_2) {
        src_1->cardinality = intersect_skewed_uint16(
            src_1->array, card_1, src_2->array, card_2, src_1->array);
    } else if (card_2 * threshold < card_1) {
        src_1->cardinality = intersect_skewed_uint16(
            src_2->array, card_2, src_1->array, card_1, src_1->array);
    } else {
        src_1->cardinality = intersect_uint16(
            src_1->array, card_1, src_2->array, card_2, src_1->array);
    }
}

static int array_container_to_uint32_array(void *vout, const array_container_t *cont,
                                    uint32_t base) {
    int outpos = 0;
    uint32_t *out = (uint32_t *)vout;
    int i = 0; for (i = 0; i < cont->cardinality; ++i) {
        const uint32_t val = base + cont->array[i];
        memcpy(out + outpos, &val,
               sizeof(uint32_t));  // should be compiled as a MOV on x64
        outpos++;
    }
    return outpos;
}

static void array_container_printf(const array_container_t *v) {
    if (v->cardinality == 0) {
        printf("{}");
        return;
    }
    printf("{");
    printf("%d", v->array[0]);
    int i ; for (i = 1; i < v->cardinality; ++i) {
        printf(",%d", v->array[i]);
    }
    printf("}");
}

static void array_container_printf_as_uint32_array(const array_container_t *v,
                                            uint32_t base) {
    if (v->cardinality == 0) {
        return;
    }
    printf("%u", v->array[0] + base);
    int i ; for (i = 1; i < v->cardinality; ++i) {
        printf(",%u", v->array[i] + base);
    }
}

/* Compute the number of runs */
static int32_t array_container_number_of_runs(const array_container_t *ac) {
    // Can SIMD work here?
    int32_t nr_runs = 0;
    int32_t prev = -2;
    const uint16_t *p;
    for (p = ac->array; p != ac->array + ac->cardinality; ++p) {
        if (*p != prev + 1) nr_runs++;
        prev = *p;
    }
    return nr_runs;
}

/**
 * Writes the underlying array to buf, outputs how many bytes were written.
 * The number of bytes written should be
 * array_container_size_in_bytes(container).
 *
 */
static int32_t array_container_write(const array_container_t *container, char *buf) {
    memcpy(buf, container->array, container->cardinality * sizeof(uint16_t));
    return array_container_size_in_bytes(container);
}

static bool array_container_is_subset(const array_container_t *container1,
                               const array_container_t *container2) {
    if (container1->cardinality > container2->cardinality) {
        return false;
    }
    int i1 = 0, i2 = 0;
    while (i1 < container1->cardinality && i2 < container2->cardinality) {
        if (container1->array[i1] == container2->array[i2]) {
            i1++;
            i2++;
        } else if (container1->array[i1] > container2->array[i2]) {
            i2++;
        } else {  // container1->array[i1] < container2->array[i2]
            return false;
        }
    }
    if (i1 == container1->cardinality) {
        return true;
    } else {
        return false;
    }
}

static int32_t array_container_read(int32_t cardinality, array_container_t *container,
                             const char *buf) {
    if (container->capacity < cardinality) {
        array_container_grow(container, cardinality, false);
    }
    container->cardinality = cardinality;
    memcpy(container->array, buf, container->cardinality * sizeof(uint16_t));

    return array_container_size_in_bytes(container);
}

static bool array_container_iterate(const array_container_t *cont, uint32_t base,
                             roaring_iterator iterator, void *ptr) {
    int i = 0; for (i = 0; i < cont->cardinality; i++)
        if (!iterator(cont->array[i] + base, ptr)) return false;
    return true;
}

static bool array_container_iterate64(const array_container_t *cont, uint32_t base,
                               roaring_iterator64 iterator, uint64_t high_bits,
                               void *ptr) {
    int i = 0; for (i = 0; i < cont->cardinality; i++)
        if (!iterator(high_bits | (uint64_t)(cont->array[i] + base), ptr))
            return false;
    return true;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/array.c */
/* begin file src/containers/mixed_union.c */
/*
 * mixed_union.c
 *
 */

#include <assert.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the union of src_1 and src_2 and write the result to
 * dst.  */
static void array_bitset_container_union(const array_container_t *src_1,
                                  const bitset_container_t *src_2,
                                  bitset_container_t *dst) {
    if (src_2 != dst) bitset_container_copy(src_2, dst);
    dst->cardinality = (int32_t)bitset_set_list_withcard(
        dst->words, dst->cardinality, src_1->array, src_1->cardinality);
}

/* Compute the union of src_1 and src_2 and write the result to
 * dst. It is allowed for src_2 to be dst.  This version does not
 * update the cardinality of dst (it is set to BITSET_UNKNOWN_CARDINALITY). */
static void array_bitset_container_lazy_union(const array_container_t *src_1,
                                       const bitset_container_t *src_2,
                                       bitset_container_t *dst) {
    if (src_2 != dst) bitset_container_copy(src_2, dst);
    bitset_set_list(dst->words, src_1->array, src_1->cardinality);
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;
}

static void run_bitset_container_union(const run_container_t *src_1,
                                const bitset_container_t *src_2,
                                bitset_container_t *dst) {
    assert(!run_container_is_full(src_1));  // catch this case upstream
    if (src_2 != dst) bitset_container_copy(src_2, dst);
    int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
        rle16_t rle = src_1->runs[rlepos];
        bitset_set_lenrange(dst->words, rle.value, rle.length);
    }
    dst->cardinality = bitset_container_compute_cardinality(dst);
}

static void run_bitset_container_lazy_union(const run_container_t *src_1,
                                     const bitset_container_t *src_2,
                                     bitset_container_t *dst) {
    assert(!run_container_is_full(src_1));  // catch this case upstream
    if (src_2 != dst) bitset_container_copy(src_2, dst);
    int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
        rle16_t rle = src_1->runs[rlepos];
        bitset_set_lenrange(dst->words, rle.value, rle.length);
    }
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;
}

// why do we leave the result as a run container??
static void array_run_container_union(const array_container_t *src_1,
                               const run_container_t *src_2,
                               run_container_t *dst) {
    if (run_container_is_full(src_2)) {
        run_container_copy(src_2, dst);
        return;
    }
    // TODO: see whether the "2*" is spurious
    run_container_grow(dst, 2 * (src_1->cardinality + src_2->n_runs), false);
    int32_t rlepos = 0;
    int32_t arraypos = 0;
    rle16_t previousrle;
    if (src_2->runs[rlepos].value <= src_1->array[arraypos]) {
        previousrle = run_container_append_first(dst, src_2->runs[rlepos]);
        rlepos++;
    } else {
        previousrle =
            run_container_append_value_first(dst, src_1->array[arraypos]);
        arraypos++;
    }
    while ((rlepos < src_2->n_runs) && (arraypos < src_1->cardinality)) {
        if (src_2->runs[rlepos].value <= src_1->array[arraypos]) {
            run_container_append(dst, src_2->runs[rlepos], &previousrle);
            rlepos++;
        } else {
            run_container_append_value(dst, src_1->array[arraypos],
                                       &previousrle);
            arraypos++;
        }
    }
    if (arraypos < src_1->cardinality) {
        while (arraypos < src_1->cardinality) {
            run_container_append_value(dst, src_1->array[arraypos],
                                       &previousrle);
            arraypos++;
        }
    } else {
        while (rlepos < src_2->n_runs) {
            run_container_append(dst, src_2->runs[rlepos], &previousrle);
            rlepos++;
        }
    }
}

static void array_run_container_inplace_union(const array_container_t *src_1,
                                       run_container_t *src_2) {
    if (run_container_is_full(src_2)) {
        return;
    }
    const int32_t maxoutput = src_1->cardinality + src_2->n_runs;
    const int32_t neededcapacity = maxoutput + src_2->n_runs;
    if (src_2->capacity < neededcapacity)
        run_container_grow(src_2, neededcapacity, true);
    memmove(src_2->runs + maxoutput, src_2->runs,
            src_2->n_runs * sizeof(rle16_t));
    rle16_t *inputsrc2 = src_2->runs + maxoutput;
    int32_t rlepos = 0;
    int32_t arraypos = 0;
    int src2nruns = src_2->n_runs;
    src_2->n_runs = 0;

    rle16_t previousrle;

    if (inputsrc2[rlepos].value <= src_1->array[arraypos]) {
        previousrle = run_container_append_first(src_2, inputsrc2[rlepos]);
        rlepos++;
    } else {
        previousrle =
            run_container_append_value_first(src_2, src_1->array[arraypos]);
        arraypos++;
    }

    while ((rlepos < src2nruns) && (arraypos < src_1->cardinality)) {
        if (inputsrc2[rlepos].value <= src_1->array[arraypos]) {
            run_container_append(src_2, inputsrc2[rlepos], &previousrle);
            rlepos++;
        } else {
            run_container_append_value(src_2, src_1->array[arraypos],
                                       &previousrle);
            arraypos++;
        }
    }
    if (arraypos < src_1->cardinality) {
        while (arraypos < src_1->cardinality) {
            run_container_append_value(src_2, src_1->array[arraypos],
                                       &previousrle);
            arraypos++;
        }
    } else {
        while (rlepos < src2nruns) {
            run_container_append(src_2, inputsrc2[rlepos], &previousrle);
            rlepos++;
        }
    }
}

static bool array_array_container_union(
    const array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int totalCardinality = src_1->cardinality + src_2->cardinality;
    if (totalCardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_create_given_capacity(totalCardinality);
        if (*dst != NULL) {
            array_container_union(src_1, src_2, CAST_array(*dst));
        } else {
            return true; // otherwise failure won't be caught
        }
        return false;  // not a bitset
    }
    *dst = bitset_container_create();
    bool returnval = true;  // expect a bitset
    if (*dst != NULL) {
        bitset_container_t *ourbitset = CAST_bitset(*dst);
        bitset_set_list(ourbitset->words, src_1->array, src_1->cardinality);
        ourbitset->cardinality = (int32_t)bitset_set_list_withcard(
            ourbitset->words, src_1->cardinality, src_2->array,
            src_2->cardinality);
        if (ourbitset->cardinality <= DEFAULT_MAX_SIZE) {
            // need to convert!
            *dst = array_container_from_bitset(ourbitset);
            bitset_container_free(ourbitset);
            returnval = false;  // not going to be a bitset
        }
    }
    return returnval;
}

static bool array_array_container_inplace_union(
    array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int totalCardinality = src_1->cardinality + src_2->cardinality;
    *dst = NULL;
    if (totalCardinality <= DEFAULT_MAX_SIZE) {
        if(src_1->capacity < totalCardinality) {
          *dst = array_container_create_given_capacity(2  * totalCardinality); // be purposefully generous
          if (*dst != NULL) {
              array_container_union(src_1, src_2, CAST_array(*dst));
          } else {
              return true; // otherwise failure won't be caught
          }
          return false;  // not a bitset
        } else {
          memmove(src_1->array + src_2->cardinality, src_1->array, src_1->cardinality * sizeof(uint16_t));
          src_1->cardinality = (int32_t)union_uint16(src_1->array + src_2->cardinality, src_1->cardinality,
                                  src_2->array, src_2->cardinality, src_1->array);
          return false; // not a bitset
        }
    }
    *dst = bitset_container_create();
    bool returnval = true;  // expect a bitset
    if (*dst != NULL) {
        bitset_container_t *ourbitset = CAST_bitset(*dst);
        bitset_set_list(ourbitset->words, src_1->array, src_1->cardinality);
        ourbitset->cardinality = (int32_t)bitset_set_list_withcard(
            ourbitset->words, src_1->cardinality, src_2->array,
            src_2->cardinality);
        if (ourbitset->cardinality <= DEFAULT_MAX_SIZE) {
            // need to convert!
            if(src_1->capacity < ourbitset->cardinality) {
              array_container_grow(src_1, ourbitset->cardinality, false);
            }

            bitset_extract_setbits_uint16(ourbitset->words, BITSET_CONTAINER_SIZE_IN_WORDS,
                                  src_1->array, 0);
            src_1->cardinality =  ourbitset->cardinality;
            *dst = src_1;
            bitset_container_free(ourbitset);
            returnval = false;  // not going to be a bitset
        }
    }
    return returnval;
}


static bool array_array_container_lazy_union(
    const array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int totalCardinality = src_1->cardinality + src_2->cardinality;
    if (totalCardinality <= ARRAY_LAZY_LOWERBOUND) {
        *dst = array_container_create_given_capacity(totalCardinality);
        if (*dst != NULL) {
            array_container_union(src_1, src_2, CAST_array(*dst));
        } else {
              return true; // otherwise failure won't be caught
        }
        return false;  // not a bitset
    }
    *dst = bitset_container_create();
    bool returnval = true;  // expect a bitset
    if (*dst != NULL) {
        bitset_container_t *ourbitset = CAST_bitset(*dst);
        bitset_set_list(ourbitset->words, src_1->array, src_1->cardinality);
        bitset_set_list(ourbitset->words, src_2->array, src_2->cardinality);
        ourbitset->cardinality = BITSET_UNKNOWN_CARDINALITY;
    }
    return returnval;
}


static bool array_array_container_lazy_inplace_union(
    array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int totalCardinality = src_1->cardinality + src_2->cardinality;
    *dst = NULL;
    if (totalCardinality <= ARRAY_LAZY_LOWERBOUND) {
        if(src_1->capacity < totalCardinality) {
          *dst = array_container_create_given_capacity(2  * totalCardinality); // be purposefully generous
          if (*dst != NULL) {
              array_container_union(src_1, src_2, CAST_array(*dst));
          } else {
            return true; // otherwise failure won't be caught
          }
          return false;  // not a bitset
        } else {
          memmove(src_1->array + src_2->cardinality, src_1->array, src_1->cardinality * sizeof(uint16_t));
          src_1->cardinality = (int32_t)union_uint16(src_1->array + src_2->cardinality, src_1->cardinality,
                                  src_2->array, src_2->cardinality, src_1->array);
          return false; // not a bitset
        }
    }
    *dst = bitset_container_create();
    bool returnval = true;  // expect a bitset
    if (*dst != NULL) {
        bitset_container_t *ourbitset = CAST_bitset(*dst);
        bitset_set_list(ourbitset->words, src_1->array, src_1->cardinality);
        bitset_set_list(ourbitset->words, src_2->array, src_2->cardinality);
        ourbitset->cardinality = BITSET_UNKNOWN_CARDINALITY;
    }
    return returnval;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_union.c */
/* begin file src/containers/convert.c */
#include <stdio.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

// file contains grubby stuff that must know impl. details of all container
// types.
static bitset_container_t *bitset_container_from_array(const array_container_t *ac) {
    bitset_container_t *ans = bitset_container_create();
    int limit = array_container_cardinality(ac);
    int i = 0; for (i = 0; i < limit; ++i) bitset_container_set(ans, ac->array[i]);
    return ans;
}

static bitset_container_t *bitset_container_from_run(const run_container_t *arr) {
    int card = run_container_cardinality(arr);
    bitset_container_t *answer = bitset_container_create();
    int rlepos; for (rlepos = 0; rlepos < arr->n_runs; ++rlepos) {
        rle16_t vl = arr->runs[rlepos];
        bitset_set_lenrange(answer->words, vl.value, vl.length);
    }
    answer->cardinality = card;
    return answer;
}

static array_container_t *array_container_from_run(const run_container_t *arr) {
    array_container_t *answer =
        array_container_create_given_capacity(run_container_cardinality(arr));
    answer->cardinality = 0;
    int rlepos; for (rlepos = 0; rlepos < arr->n_runs; ++rlepos) {
        int run_start = arr->runs[rlepos].value;
        int run_end = run_start + arr->runs[rlepos].length;

        int run_value; for (run_value = run_start; run_value <= run_end; ++run_value) {
            answer->array[answer->cardinality++] = (uint16_t)run_value;
        }
    }
    return answer;
}

static array_container_t *array_container_from_bitset(const bitset_container_t *bits) {
    array_container_t *result =
        array_container_create_given_capacity(bits->cardinality);
    result->cardinality = bits->cardinality;
    //  sse version ends up being slower here
    // (bitset_extract_setbits_sse_uint16)
    // because of the sparsity of the data
    bitset_extract_setbits_uint16(bits->words, BITSET_CONTAINER_SIZE_IN_WORDS,
                                  result->array, 0);
    return result;
}

/* assumes that container has adequate space.  Run from [s,e] (inclusive) */
static void add_run(run_container_t *rc, int s, int e) {
    rc->runs[rc->n_runs].value = s;
    rc->runs[rc->n_runs].length = e - s;
    rc->n_runs++;
}

static run_container_t *run_container_from_array(const array_container_t *c) {
    int32_t n_runs = array_container_number_of_runs(c);
    run_container_t *answer = run_container_create_given_capacity(n_runs);
    int prev = -2;
    int run_start = -1;
    int32_t card = c->cardinality;
    if (card == 0) return answer;
    int i = 0; for (i = 0; i < card; ++i) {
        const uint16_t cur_val = c->array[i];
        if (cur_val != prev + 1) {
            // new run starts; flush old one, if any
            if (run_start != -1) add_run(answer, run_start, prev);
            run_start = cur_val;
        }
        prev = c->array[i];
    }
    // now prev is the last seen value
    add_run(answer, run_start, prev);
    // assert(run_container_cardinality(answer) == c->cardinality);
    return answer;
}

/**
 * Convert the runcontainer to either a Bitmap or an Array Container, depending
 * on the cardinality.  Frees the container.
 * Allocates and returns new container, which caller is responsible for freeing.
 * It does not free the run container.
 */
static container_t *convert_to_bitset_or_array_container(
    run_container_t *rc, int32_t card,
    uint8_t *resulttype
){
    if (card <= DEFAULT_MAX_SIZE) {
        array_container_t *answer = array_container_create_given_capacity(card);
        answer->cardinality = 0;
        int rlepos; for (rlepos = 0; rlepos < rc->n_runs; ++rlepos) {
            uint16_t run_start = rc->runs[rlepos].value;
            uint16_t run_end = run_start + rc->runs[rlepos].length;
            uint16_t run_value; for (run_value = run_start; run_value <= run_end;
                 ++run_value) {
                answer->array[answer->cardinality++] = run_value;
            }
        }
        assert(card == answer->cardinality);
        *resulttype = ARRAY_CONTAINER_TYPE;
        //run_container_free(r);
        return answer;
    }
    bitset_container_t *answer = bitset_container_create();
    int rlepos; for (rlepos = 0; rlepos < rc->n_runs; ++rlepos) {
        uint16_t run_start = rc->runs[rlepos].value;
        bitset_set_lenrange(answer->words, run_start, rc->runs[rlepos].length);
    }
    answer->cardinality = card;
    *resulttype = BITSET_CONTAINER_TYPE;
    //run_container_free(r);
    return answer;
}

/* Converts a run container to either an array or a bitset, IF it saves space.
 */
/* If a conversion occurs, the caller is responsible to free the original
 * container and
 * he becomes responsible to free the new one. */
static container_t *convert_run_to_efficient_container(
    run_container_t *c,
    uint8_t *typecode_after
){
    int32_t size_as_run_container =
        run_container_serialized_size_in_bytes(c->n_runs);

    int32_t size_as_bitset_container =
        bitset_container_serialized_size_in_bytes();
    int32_t card = run_container_cardinality(c);
    int32_t size_as_array_container =
        array_container_serialized_size_in_bytes(card);

    int32_t min_size_non_run =
        size_as_bitset_container < size_as_array_container
            ? size_as_bitset_container
            : size_as_array_container;
    if (size_as_run_container <= min_size_non_run) {  // no conversion
        *typecode_after = RUN_CONTAINER_TYPE;
        return c;
    }
    if (card <= DEFAULT_MAX_SIZE) {
        // to array
        array_container_t *answer = array_container_create_given_capacity(card);
        answer->cardinality = 0;
        int rlepos; for (rlepos = 0; rlepos < c->n_runs; ++rlepos) {
            int run_start = c->runs[rlepos].value;
            int run_end = run_start + c->runs[rlepos].length;

            int run_value; for (run_value = run_start; run_value <= run_end; ++run_value) {
                answer->array[answer->cardinality++] = (uint16_t)run_value;
            }
        }
        *typecode_after = ARRAY_CONTAINER_TYPE;
        return answer;
    }

    // else to bitset
    bitset_container_t *answer = bitset_container_create();

    int rlepos; for (rlepos = 0; rlepos < c->n_runs; ++rlepos) {
        int start = c->runs[rlepos].value;
        int end = start + c->runs[rlepos].length;
        bitset_set_range(answer->words, start, end + 1);
    }
    answer->cardinality = card;
    *typecode_after = BITSET_CONTAINER_TYPE;
    return answer;
}

// like convert_run_to_efficient_container but frees the old result if needed
static container_t *convert_run_to_efficient_container_and_free(
    run_container_t *c,
    uint8_t *typecode_after
){
    container_t *answer = convert_run_to_efficient_container(c, typecode_after);
    if (answer != c) run_container_free(c);
    return answer;
}

/* once converted, the original container is disposed here, rather than
   in roaring_array
*/

// TODO: split into run-  array-  and bitset-  subfunctions for sanity;
// a few function calls won't really matter.

static container_t *convert_run_optimize(
    container_t *c, uint8_t typecode_original,
    uint8_t *typecode_after
){
    if (typecode_original == RUN_CONTAINER_TYPE) {
        container_t *newc = convert_run_to_efficient_container(
                                    CAST_run(c), typecode_after);
        if (newc != c) {
            container_free(c, typecode_original);
        }
        return newc;
    } else if (typecode_original == ARRAY_CONTAINER_TYPE) {
        // it might need to be converted to a run container.
        array_container_t *c_qua_array = CAST_array(c);
        int32_t n_runs = array_container_number_of_runs(c_qua_array);
        int32_t size_as_run_container =
            run_container_serialized_size_in_bytes(n_runs);
        int32_t card = array_container_cardinality(c_qua_array);
        int32_t size_as_array_container =
            array_container_serialized_size_in_bytes(card);

        if (size_as_run_container >= size_as_array_container) {
            *typecode_after = ARRAY_CONTAINER_TYPE;
            return c;
        }
        // else convert array to run container
        run_container_t *answer = run_container_create_given_capacity(n_runs);
        int prev = -2;
        int run_start = -1;

        assert(card > 0);
        int i = 0; for (i = 0; i < card; ++i) {
            uint16_t cur_val = c_qua_array->array[i];
            if (cur_val != prev + 1) {
                // new run starts; flush old one, if any
                if (run_start != -1) add_run(answer, run_start, prev);
                run_start = cur_val;
            }
            prev = c_qua_array->array[i];
        }
        assert(run_start >= 0);
        // now prev is the last seen value
        add_run(answer, run_start, prev);
        *typecode_after = RUN_CONTAINER_TYPE;
        array_container_free(c_qua_array);
        return answer;
    } else if (typecode_original ==
               BITSET_CONTAINER_TYPE) {  // run conversions on bitset
        // does bitset need conversion to run?
        bitset_container_t *c_qua_bitset = CAST_bitset(c);
        int32_t n_runs = bitset_container_number_of_runs(c_qua_bitset);
        int32_t size_as_run_container =
            run_container_serialized_size_in_bytes(n_runs);
        int32_t size_as_bitset_container =
            bitset_container_serialized_size_in_bytes();

        if (size_as_bitset_container <= size_as_run_container) {
            // no conversion needed.
            *typecode_after = BITSET_CONTAINER_TYPE;
            return c;
        }
        // bitset to runcontainer (ported from Java  RunContainer(
        // BitmapContainer bc, int nbrRuns))
        assert(n_runs > 0);  // no empty bitmaps
        run_container_t *answer = run_container_create_given_capacity(n_runs);

        int long_ctr = 0;
        uint64_t cur_word = c_qua_bitset->words[0];
        while (true) {
            while (cur_word == UINT64_C(0) &&
                   long_ctr < BITSET_CONTAINER_SIZE_IN_WORDS - 1)
                cur_word = c_qua_bitset->words[++long_ctr];

            if (cur_word == UINT64_C(0)) {
                bitset_container_free(c_qua_bitset);
                *typecode_after = RUN_CONTAINER_TYPE;
                return answer;
            }

            int local_run_start = __builtin_ctzll(cur_word);
            int run_start = local_run_start + 64 * long_ctr;
            uint64_t cur_word_with_1s = cur_word | (cur_word - 1);

            int run_end = 0;
            while (cur_word_with_1s == UINT64_C(0xFFFFFFFFFFFFFFFF) &&
                   long_ctr < BITSET_CONTAINER_SIZE_IN_WORDS - 1)
                cur_word_with_1s = c_qua_bitset->words[++long_ctr];

            if (cur_word_with_1s == UINT64_C(0xFFFFFFFFFFFFFFFF)) {
                run_end = 64 + long_ctr * 64;  // exclusive, I guess
                add_run(answer, run_start, run_end - 1);
                bitset_container_free(c_qua_bitset);
                *typecode_after = RUN_CONTAINER_TYPE;
                return answer;
            }
            int local_run_end = __builtin_ctzll(~cur_word_with_1s);
            run_end = local_run_end + long_ctr * 64;
            add_run(answer, run_start, run_end - 1);
            cur_word = cur_word_with_1s & (cur_word_with_1s + 1);
        }
        return answer;
    } else {
        assert(false);
        __builtin_unreachable();
        return NULL;
    }
}

static container_t *container_from_run_range(
    const run_container_t *run,
    uint32_t min, uint32_t max, uint8_t *typecode_after
){
    // We expect most of the time to end up with a bitset container
    bitset_container_t *bitset = bitset_container_create();
    *typecode_after = BITSET_CONTAINER_TYPE;
    int32_t union_cardinality = 0;
    int32_t i; for (i = 0; i < run->n_runs; ++i) {
        uint32_t rle_min = run->runs[i].value;
        uint32_t rle_max = rle_min + run->runs[i].length;
        bitset_set_lenrange(bitset->words, rle_min, rle_max - rle_min);
        union_cardinality += run->runs[i].length + 1;
    }
    union_cardinality += max - min + 1;
    union_cardinality -= bitset_lenrange_cardinality(bitset->words, min, max-min);
    bitset_set_lenrange(bitset->words, min, max - min);
    bitset->cardinality = union_cardinality;
    if(bitset->cardinality <= DEFAULT_MAX_SIZE) {
        // we need to convert to an array container
        array_container_t * array = array_container_from_bitset(bitset);
        *typecode_after = ARRAY_CONTAINER_TYPE;
        bitset_container_free(bitset);
        return array;
    }
    return bitset;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/convert.c */
/* begin file src/containers/run.c */
#include <stdio.h>
#include <stdlib.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

extern inline uint16_t run_container_minimum(const run_container_t *run);
extern inline uint16_t run_container_maximum(const run_container_t *run);
extern inline int32_t interleavedBinarySearch(const rle16_t *array,
                                              int32_t lenarray, uint16_t ikey);
extern inline bool run_container_contains(const run_container_t *run,
                                          uint16_t pos);
extern inline int run_container_index_equalorlarger(const run_container_t *arr, uint16_t x);
extern inline bool run_container_is_full(const run_container_t *run);
extern inline bool run_container_nonzero_cardinality(const run_container_t *rc);
extern inline void run_container_clear(run_container_t *run);
extern inline int32_t run_container_serialized_size_in_bytes(int32_t num_runs);
extern inline run_container_t *run_container_create_range(uint32_t start,
                                                   uint32_t stop);
extern inline int run_container_cardinality(const run_container_t *run);


static bool run_container_add(run_container_t *run, uint16_t pos) {
    int32_t index = interleavedBinarySearch(run->runs, run->n_runs, pos);
    if (index >= 0) return false;  // already there
    index = -index - 2;            // points to preceding value, possibly -1
    if (index >= 0) {              // possible match
        int32_t offset = pos - run->runs[index].value;
        int32_t le = run->runs[index].length;
        if (offset <= le) return false;  // already there
        if (offset == le + 1) {
            // we may need to fuse
            if (index + 1 < run->n_runs) {
                if (run->runs[index + 1].value == pos + 1) {
                    // indeed fusion is needed
                    run->runs[index].length = run->runs[index + 1].value +
                                              run->runs[index + 1].length -
                                              run->runs[index].value;
                    recoverRoomAtIndex(run, (uint16_t)(index + 1));
                    return true;
                }
            }
            run->runs[index].length++;
            return true;
        }
        if (index + 1 < run->n_runs) {
            // we may need to fuse
            if (run->runs[index + 1].value == pos + 1) {
                // indeed fusion is needed
                run->runs[index + 1].value = pos;
                run->runs[index + 1].length = run->runs[index + 1].length + 1;
                return true;
            }
        }
    }
    if (index == -1) {
        // we may need to extend the first run
        if (0 < run->n_runs) {
            if (run->runs[0].value == pos + 1) {
                run->runs[0].length++;
                run->runs[0].value--;
                return true;
            }
        }
    }
    makeRoomAtIndex(run, (uint16_t)(index + 1));
    run->runs[index + 1].value = pos;
    run->runs[index + 1].length = 0;
    return true;
}

/* Create a new run container. Return NULL in case of failure. */
static run_container_t *run_container_create_given_capacity(int32_t size) {
    run_container_t *run;
    /* Allocate the run container itself. */
    if ((run = (run_container_t *)ndpi_malloc(sizeof(run_container_t))) == NULL) {
        return NULL;
    }
    if (size <= 0 ) { // we don't want to rely on malloc(0)
        run->runs = NULL;
    } else if ((run->runs = (rle16_t *)ndpi_malloc(sizeof(rle16_t) * size)) == NULL) {
        ndpi_free(run);
        return NULL;
    }
    run->capacity = size;
    run->n_runs = 0;
    return run;
}

static int run_container_shrink_to_fit(run_container_t *src) {
    if (src->n_runs == src->capacity) return 0;  // nothing to do
    int savings = src->capacity - src->n_runs;
    int old_capacity = src->capacity;
    src->capacity = src->n_runs;
    rle16_t *oldruns = src->runs;
    src->runs = (rle16_t *)ndpi_realloc(oldruns, old_capacity * sizeof(rle16_t), src->capacity * sizeof(rle16_t));
    if (src->runs == NULL) ndpi_free(oldruns);  // should never happen?
    return savings;
}
/* Create a new run container. Return NULL in case of failure. */
static run_container_t *run_container_create(void) {
    return run_container_create_given_capacity(RUN_DEFAULT_INIT_SIZE);
}

static run_container_t *run_container_clone(const run_container_t *src) {
    run_container_t *run = run_container_create_given_capacity(src->capacity);
    if (run == NULL) return NULL;
    run->capacity = src->capacity;
    run->n_runs = src->n_runs;
    memcpy(run->runs, src->runs, src->n_runs * sizeof(rle16_t));
    return run;
}

/* Free memory. */
static void run_container_free(run_container_t *run) {
    if(run->runs != NULL) {// Jon Strabala reports that some tools complain otherwise
      ndpi_free(run->runs);
      run->runs = NULL;  // pedantic
    }
    ndpi_free(run);
}

static void run_container_grow(run_container_t *run, int32_t min, bool copy) {
    int32_t newCapacity =
        (run->capacity == 0)
            ? RUN_DEFAULT_INIT_SIZE
            : run->capacity < 64 ? run->capacity * 2
                                 : run->capacity < 1024 ? run->capacity * 3 / 2
                                                        : run->capacity * 5 / 4;
    int32_t old_capacity = run->capacity;
    if (newCapacity < min) newCapacity = min;
    run->capacity = newCapacity;
    assert(run->capacity >= min);
    if (copy) {
        rle16_t *oldruns = run->runs;
        run->runs =
            (rle16_t *)ndpi_realloc(oldruns, old_capacity * sizeof(rle16_t), run->capacity * sizeof(rle16_t));
        if (run->runs == NULL) ndpi_free(oldruns);
    } else {
        // Jon Strabala reports that some tools complain otherwise
        if (run->runs != NULL) {
          ndpi_free(run->runs);
        }
        run->runs = (rle16_t *)ndpi_malloc(run->capacity * sizeof(rle16_t));
    }
    // handle the case where realloc fails
    if (run->runs == NULL) {
      fprintf(stderr, "could not allocate memory\n");
    }
    assert(run->runs != NULL);
}

/* copy one container into another */
static void run_container_copy(const run_container_t *src, run_container_t *dst) {
    const int32_t n_runs = src->n_runs;
    if (src->n_runs > dst->capacity) {
        run_container_grow(dst, n_runs, false);
    }
    dst->n_runs = n_runs;
    memcpy(dst->runs, src->runs, sizeof(rle16_t) * n_runs);
}

/* Compute the union of `src_1' and `src_2' and write the result to `dst'
 * It is assumed that `dst' is distinct from both `src_1' and `src_2'. */
static void run_container_union(const run_container_t *src_1,
                         const run_container_t *src_2, run_container_t *dst) {
    // TODO: this could be a lot more efficient

    // we start out with inexpensive checks
    const bool if1 = run_container_is_full(src_1);
    const bool if2 = run_container_is_full(src_2);
    if (if1 || if2) {
        if (if1) {
            run_container_copy(src_1, dst);
            return;
        }
        if (if2) {
            run_container_copy(src_2, dst);
            return;
        }
    }
    const int32_t neededcapacity = src_1->n_runs + src_2->n_runs;
    if (dst->capacity < neededcapacity)
        run_container_grow(dst, neededcapacity, false);
    dst->n_runs = 0;
    int32_t rlepos = 0;
    int32_t xrlepos = 0;

    rle16_t previousrle;
    if (src_1->runs[rlepos].value <= src_2->runs[xrlepos].value) {
        previousrle = run_container_append_first(dst, src_1->runs[rlepos]);
        rlepos++;
    } else {
        previousrle = run_container_append_first(dst, src_2->runs[xrlepos]);
        xrlepos++;
    }

    while ((xrlepos < src_2->n_runs) && (rlepos < src_1->n_runs)) {
        rle16_t newrl;
        if (src_1->runs[rlepos].value <= src_2->runs[xrlepos].value) {
            newrl = src_1->runs[rlepos];
            rlepos++;
        } else {
            newrl = src_2->runs[xrlepos];
            xrlepos++;
        }
        run_container_append(dst, newrl, &previousrle);
    }
    while (xrlepos < src_2->n_runs) {
        run_container_append(dst, src_2->runs[xrlepos], &previousrle);
        xrlepos++;
    }
    while (rlepos < src_1->n_runs) {
        run_container_append(dst, src_1->runs[rlepos], &previousrle);
        rlepos++;
    }
}

/* Compute the union of `src_1' and `src_2' and write the result to `src_1'
 */
static void run_container_union_inplace(run_container_t *src_1,
                                 const run_container_t *src_2) {
    // TODO: this could be a lot more efficient

    // we start out with inexpensive checks
    const bool if1 = run_container_is_full(src_1);
    const bool if2 = run_container_is_full(src_2);
    if (if1 || if2) {
        if (if1) {
            return;
        }
        if (if2) {
            run_container_copy(src_2, src_1);
            return;
        }
    }
    // we move the data to the end of the current array
    const int32_t maxoutput = src_1->n_runs + src_2->n_runs;
    const int32_t neededcapacity = maxoutput + src_1->n_runs;
    if (src_1->capacity < neededcapacity)
        run_container_grow(src_1, neededcapacity, true);
    memmove(src_1->runs + maxoutput, src_1->runs,
            src_1->n_runs * sizeof(rle16_t));
    rle16_t *inputsrc1 = src_1->runs + maxoutput;
    const int32_t input1nruns = src_1->n_runs;
    src_1->n_runs = 0;
    int32_t rlepos = 0;
    int32_t xrlepos = 0;

    rle16_t previousrle;
    if (inputsrc1[rlepos].value <= src_2->runs[xrlepos].value) {
        previousrle = run_container_append_first(src_1, inputsrc1[rlepos]);
        rlepos++;
    } else {
        previousrle = run_container_append_first(src_1, src_2->runs[xrlepos]);
        xrlepos++;
    }
    while ((xrlepos < src_2->n_runs) && (rlepos < input1nruns)) {
        rle16_t newrl;
        if (inputsrc1[rlepos].value <= src_2->runs[xrlepos].value) {
            newrl = inputsrc1[rlepos];
            rlepos++;
        } else {
            newrl = src_2->runs[xrlepos];
            xrlepos++;
        }
        run_container_append(src_1, newrl, &previousrle);
    }
    while (xrlepos < src_2->n_runs) {
        run_container_append(src_1, src_2->runs[xrlepos], &previousrle);
        xrlepos++;
    }
    while (rlepos < input1nruns) {
        run_container_append(src_1, inputsrc1[rlepos], &previousrle);
        rlepos++;
    }
}

/* Compute the symmetric difference of `src_1' and `src_2' and write the result
 * to `dst'
 * It is assumed that `dst' is distinct from both `src_1' and `src_2'. */
static void run_container_xor(const run_container_t *src_1,
                       const run_container_t *src_2, run_container_t *dst) {
    // don't bother to convert xor with full range into negation
    // since negation is implemented similarly

    const int32_t neededcapacity = src_1->n_runs + src_2->n_runs;
    if (dst->capacity < neededcapacity)
        run_container_grow(dst, neededcapacity, false);

    int32_t pos1 = 0;
    int32_t pos2 = 0;
    dst->n_runs = 0;

    while ((pos1 < src_1->n_runs) && (pos2 < src_2->n_runs)) {
        if (src_1->runs[pos1].value <= src_2->runs[pos2].value) {
            run_container_smart_append_exclusive(dst, src_1->runs[pos1].value,
                                                 src_1->runs[pos1].length);
            pos1++;
        } else {
            run_container_smart_append_exclusive(dst, src_2->runs[pos2].value,
                                                 src_2->runs[pos2].length);
            pos2++;
        }
    }
    while (pos1 < src_1->n_runs) {
        run_container_smart_append_exclusive(dst, src_1->runs[pos1].value,
                                             src_1->runs[pos1].length);
        pos1++;
    }

    while (pos2 < src_2->n_runs) {
        run_container_smart_append_exclusive(dst, src_2->runs[pos2].value,
                                             src_2->runs[pos2].length);
        pos2++;
    }
}

/* Compute the intersection of src_1 and src_2 and write the result to
 * dst. It is assumed that dst is distinct from both src_1 and src_2. */
static void run_container_intersection(const run_container_t *src_1,
                                const run_container_t *src_2,
                                run_container_t *dst) {
    const bool if1 = run_container_is_full(src_1);
    const bool if2 = run_container_is_full(src_2);
    if (if1 || if2) {
        if (if1) {
            run_container_copy(src_2, dst);
            return;
        }
        if (if2) {
            run_container_copy(src_1, dst);
            return;
        }
    }
    // TODO: this could be a lot more efficient, could use SIMD optimizations
    const int32_t neededcapacity = src_1->n_runs + src_2->n_runs;
    if (dst->capacity < neededcapacity)
        run_container_grow(dst, neededcapacity, false);
    dst->n_runs = 0;
    int32_t rlepos = 0;
    int32_t xrlepos = 0;
    int32_t start = src_1->runs[rlepos].value;
    int32_t end = start + src_1->runs[rlepos].length + 1;
    int32_t xstart = src_2->runs[xrlepos].value;
    int32_t xend = xstart + src_2->runs[xrlepos].length + 1;
    while ((rlepos < src_1->n_runs) && (xrlepos < src_2->n_runs)) {
        if (end <= xstart) {
            ++rlepos;
            if (rlepos < src_1->n_runs) {
                start = src_1->runs[rlepos].value;
                end = start + src_1->runs[rlepos].length + 1;
            }
        } else if (xend <= start) {
            ++xrlepos;
            if (xrlepos < src_2->n_runs) {
                xstart = src_2->runs[xrlepos].value;
                xend = xstart + src_2->runs[xrlepos].length + 1;
            }
        } else {  // they overlap
            const int32_t lateststart = start > xstart ? start : xstart;
            int32_t earliestend;
            if (end == xend) {  // improbable
                earliestend = end;
                rlepos++;
                xrlepos++;
                if (rlepos < src_1->n_runs) {
                    start = src_1->runs[rlepos].value;
                    end = start + src_1->runs[rlepos].length + 1;
                }
                if (xrlepos < src_2->n_runs) {
                    xstart = src_2->runs[xrlepos].value;
                    xend = xstart + src_2->runs[xrlepos].length + 1;
                }
            } else if (end < xend) {
                earliestend = end;
                rlepos++;
                if (rlepos < src_1->n_runs) {
                    start = src_1->runs[rlepos].value;
                    end = start + src_1->runs[rlepos].length + 1;
                }

            } else {  // end > xend
                earliestend = xend;
                xrlepos++;
                if (xrlepos < src_2->n_runs) {
                    xstart = src_2->runs[xrlepos].value;
                    xend = xstart + src_2->runs[xrlepos].length + 1;
                }
            }
            dst->runs[dst->n_runs].value = (uint16_t)lateststart;
            dst->runs[dst->n_runs].length =
                (uint16_t)(earliestend - lateststart - 1);
            dst->n_runs++;
        }
    }
}

/* Compute the size of the intersection of src_1 and src_2 . */
static int run_container_intersection_cardinality(const run_container_t *src_1,
                                           const run_container_t *src_2) {
    const bool if1 = run_container_is_full(src_1);
    const bool if2 = run_container_is_full(src_2);
    if (if1 || if2) {
        if (if1) {
            return run_container_cardinality(src_2);
        }
        if (if2) {
            return run_container_cardinality(src_1);
        }
    }
    int answer = 0;
    int32_t rlepos = 0;
    int32_t xrlepos = 0;
    int32_t start = src_1->runs[rlepos].value;
    int32_t end = start + src_1->runs[rlepos].length + 1;
    int32_t xstart = src_2->runs[xrlepos].value;
    int32_t xend = xstart + src_2->runs[xrlepos].length + 1;
    while ((rlepos < src_1->n_runs) && (xrlepos < src_2->n_runs)) {
        if (end <= xstart) {
            ++rlepos;
            if (rlepos < src_1->n_runs) {
                start = src_1->runs[rlepos].value;
                end = start + src_1->runs[rlepos].length + 1;
            }
        } else if (xend <= start) {
            ++xrlepos;
            if (xrlepos < src_2->n_runs) {
                xstart = src_2->runs[xrlepos].value;
                xend = xstart + src_2->runs[xrlepos].length + 1;
            }
        } else {  // they overlap
            const int32_t lateststart = start > xstart ? start : xstart;
            int32_t earliestend;
            if (end == xend) {  // improbable
                earliestend = end;
                rlepos++;
                xrlepos++;
                if (rlepos < src_1->n_runs) {
                    start = src_1->runs[rlepos].value;
                    end = start + src_1->runs[rlepos].length + 1;
                }
                if (xrlepos < src_2->n_runs) {
                    xstart = src_2->runs[xrlepos].value;
                    xend = xstart + src_2->runs[xrlepos].length + 1;
                }
            } else if (end < xend) {
                earliestend = end;
                rlepos++;
                if (rlepos < src_1->n_runs) {
                    start = src_1->runs[rlepos].value;
                    end = start + src_1->runs[rlepos].length + 1;
                }

            } else {  // end > xend
                earliestend = xend;
                xrlepos++;
                if (xrlepos < src_2->n_runs) {
                    xstart = src_2->runs[xrlepos].value;
                    xend = xstart + src_2->runs[xrlepos].length + 1;
                }
            }
            answer += earliestend - lateststart;
        }
    }
    return answer;
}

static bool run_container_intersect(const run_container_t *src_1,
                                const run_container_t *src_2) {
    const bool if1 = run_container_is_full(src_1);
    const bool if2 = run_container_is_full(src_2);
    if (if1 || if2) {
        if (if1) {
            return !run_container_empty(src_2);
        }
        if (if2) {
        	return !run_container_empty(src_1);
        }
    }
    int32_t rlepos = 0;
    int32_t xrlepos = 0;
    int32_t start = src_1->runs[rlepos].value;
    int32_t end = start + src_1->runs[rlepos].length + 1;
    int32_t xstart = src_2->runs[xrlepos].value;
    int32_t xend = xstart + src_2->runs[xrlepos].length + 1;
    while ((rlepos < src_1->n_runs) && (xrlepos < src_2->n_runs)) {
        if (end <= xstart) {
            ++rlepos;
            if (rlepos < src_1->n_runs) {
                start = src_1->runs[rlepos].value;
                end = start + src_1->runs[rlepos].length + 1;
            }
        } else if (xend <= start) {
            ++xrlepos;
            if (xrlepos < src_2->n_runs) {
                xstart = src_2->runs[xrlepos].value;
                xend = xstart + src_2->runs[xrlepos].length + 1;
            }
        } else {  // they overlap
            return true;
        }
    }
    return false;
}


/* Compute the difference of src_1 and src_2 and write the result to
 * dst. It is assumed that dst is distinct from both src_1 and src_2. */
static void run_container_andnot(const run_container_t *src_1,
                          const run_container_t *src_2, run_container_t *dst) {
    // following Java implementation as of June 2016

    if (dst->capacity < src_1->n_runs + src_2->n_runs)
        run_container_grow(dst, src_1->n_runs + src_2->n_runs, false);

    dst->n_runs = 0;

    int rlepos1 = 0;
    int rlepos2 = 0;
    int32_t start = src_1->runs[rlepos1].value;
    int32_t end = start + src_1->runs[rlepos1].length + 1;
    int32_t start2 = src_2->runs[rlepos2].value;
    int32_t end2 = start2 + src_2->runs[rlepos2].length + 1;

    while ((rlepos1 < src_1->n_runs) && (rlepos2 < src_2->n_runs)) {
        if (end <= start2) {
            // output the first run
            dst->runs[dst->n_runs++] = MAKE_RLE16(start, end - start - 1);
            rlepos1++;
            if (rlepos1 < src_1->n_runs) {
                start = src_1->runs[rlepos1].value;
                end = start + src_1->runs[rlepos1].length + 1;
            }
        } else if (end2 <= start) {
            // exit the second run
            rlepos2++;
            if (rlepos2 < src_2->n_runs) {
                start2 = src_2->runs[rlepos2].value;
                end2 = start2 + src_2->runs[rlepos2].length + 1;
            }
        } else {
            if (start < start2) {
                dst->runs[dst->n_runs++] =
                    MAKE_RLE16(start, start2 - start - 1);
            }
            if (end2 < end) {
                start = end2;
            } else {
                rlepos1++;
                if (rlepos1 < src_1->n_runs) {
                    start = src_1->runs[rlepos1].value;
                    end = start + src_1->runs[rlepos1].length + 1;
                }
            }
        }
    }
    if (rlepos1 < src_1->n_runs) {
        dst->runs[dst->n_runs++] = MAKE_RLE16(start, end - start - 1);
        rlepos1++;
        if (rlepos1 < src_1->n_runs) {
            memcpy(dst->runs + dst->n_runs, src_1->runs + rlepos1,
                   sizeof(rle16_t) * (src_1->n_runs - rlepos1));
            dst->n_runs += src_1->n_runs - rlepos1;
        }
    }
}

static int run_container_to_uint32_array(void *vout, const run_container_t *cont,
                                  uint32_t base) {
    int outpos = 0;
    uint32_t *out = (uint32_t *)vout;
    int i = 0; for (i = 0; i < cont->n_runs; ++i) {
        uint32_t run_start = base + cont->runs[i].value;
        uint16_t le = cont->runs[i].length;
        int j; for (j = 0; j <= le; ++j) {
            uint32_t val = run_start + j;
            memcpy(out + outpos, &val,
                   sizeof(uint32_t));  // should be compiled as a MOV on x64
            outpos++;
        }
    }
    return outpos;
}

/*
 * Print this container using printf (useful for debugging).
 */
static void run_container_printf(const run_container_t *cont) {
    int i = 0; for (i = 0; i < cont->n_runs; ++i) {
        uint16_t run_start = cont->runs[i].value;
        uint16_t le = cont->runs[i].length;
        printf("[%d,%d]", run_start, run_start + le);
    }
}

/*
 * Print this container using printf as a comma-separated list of 32-bit
 * integers starting at base.
 */
static void run_container_printf_as_uint32_array(const run_container_t *cont,
                                          uint32_t base) {
    if (cont->n_runs == 0) return;
    {
        uint32_t run_start = base + cont->runs[0].value;
        uint16_t le = cont->runs[0].length;
        printf("%u", run_start);
        uint32_t j; for (j = 1; j <= le; ++j) printf(",%u", run_start + j);
    }
    int32_t i; for (i = 1; i < cont->n_runs; ++i) {
        uint32_t run_start = base + cont->runs[i].value;
        uint16_t le = cont->runs[i].length;
        uint32_t j; for (j = 0; j <= le; ++j) printf(",%u", run_start + j);
    }
}

static int32_t run_container_write(const run_container_t *container, char *buf) {
    memcpy(buf, &container->n_runs, sizeof(uint16_t));
    memcpy(buf + sizeof(uint16_t), container->runs,
           container->n_runs * sizeof(rle16_t));
    return run_container_size_in_bytes(container);
}

static int32_t run_container_read(int32_t cardinality, run_container_t *container,
                           const char *buf) {
    (void)cardinality;
    memcpy(&container->n_runs, buf, sizeof(uint16_t));
    if (container->n_runs > container->capacity)
        run_container_grow(container, container->n_runs, false);
    if(container->n_runs > 0) {
      memcpy(container->runs, buf + sizeof(uint16_t),
           container->n_runs * sizeof(rle16_t));
    }
    return run_container_size_in_bytes(container);
}

static bool run_container_iterate(const run_container_t *cont, uint32_t base,
                           roaring_iterator iterator, void *ptr) {
    int i = 0; for (i = 0; i < cont->n_runs; ++i) {
        uint32_t run_start = base + cont->runs[i].value;
        uint16_t le = cont->runs[i].length;

        int j; for (j = 0; j <= le; ++j)
            if (!iterator(run_start + j, ptr)) return false;
    }
    return true;
}

static bool run_container_iterate64(const run_container_t *cont, uint32_t base,
                             roaring_iterator64 iterator, uint64_t high_bits,
                             void *ptr) {
    int i = 0; for (i = 0; i < cont->n_runs; ++i) {
        uint32_t run_start = base + cont->runs[i].value;
        uint16_t le = cont->runs[i].length;

        int j; for (j = 0; j <= le; ++j)
            if (!iterator(high_bits | (uint64_t)(run_start + j), ptr))
                return false;
    }
    return true;
}

static bool run_container_is_subset(const run_container_t *container1,
                             const run_container_t *container2) {
    int i1 = 0, i2 = 0;
    while (i1 < container1->n_runs && i2 < container2->n_runs) {
        int start1 = container1->runs[i1].value;
        int stop1 = start1 + container1->runs[i1].length;
        int start2 = container2->runs[i2].value;
        int stop2 = start2 + container2->runs[i2].length;
        if (start1 < start2) {
            return false;
        } else {  // start1 >= start2
            if (stop1 < stop2) {
                i1++;
            } else if (stop1 == stop2) {
                i1++;
                i2++;
            } else {  // stop1 > stop2
                i2++;
            }
        }
    }
    if (i1 == container1->n_runs) {
        return true;
    } else {
        return false;
    }
}

// TODO: write smart_append_exclusive version to match the overloaded 1 param
// Java version (or  is it even used?)

// follows the Java implementation closely
// length is the rle-value.  Ie, run [10,12) uses a length value 1.
static void run_container_smart_append_exclusive(run_container_t *src,
                                          const uint16_t start,
                                          const uint16_t length) {
    int old_end;
    rle16_t *last_run = src->n_runs ? src->runs + (src->n_runs - 1) : NULL;
    rle16_t *appended_last_run = src->runs + src->n_runs;

    if (!src->n_runs ||
        (start > (old_end = last_run->value + last_run->length + 1))) {
        *appended_last_run = MAKE_RLE16(start, length);
        src->n_runs++;
        return;
    }
    if (old_end == start) {
        // we merge
        last_run->length += (length + 1);
        return;
    }
    int new_end = start + length + 1;

    if (start == last_run->value) {
        // wipe out previous
        if (new_end < old_end) {
            *last_run = MAKE_RLE16(new_end, old_end - new_end - 1);
            return;
        } else if (new_end > old_end) {
            *last_run = MAKE_RLE16(old_end, new_end - old_end - 1);
            return;
        } else {
            src->n_runs--;
            return;
        }
    }
    last_run->length = start - last_run->value - 1;
    if (new_end < old_end) {
        *appended_last_run = MAKE_RLE16(new_end, old_end - new_end - 1);
        src->n_runs++;
    } else if (new_end > old_end) {
        *appended_last_run = MAKE_RLE16(old_end, new_end - old_end - 1);
        src->n_runs++;
    }
}

static bool run_container_select(const run_container_t *container,
                          uint32_t *start_rank, uint32_t rank,
                          uint32_t *element) {
    int i = 0; for (i = 0; i < container->n_runs; i++) {
        uint16_t length = container->runs[i].length;
        if (rank <= *start_rank + length) {
            uint16_t value = container->runs[i].value;
            *element = value + rank - (*start_rank);
            return true;
        } else
            *start_rank += length + 1;
    }
    return false;
}

static int run_container_rank(const run_container_t *container, uint16_t x) {
    int sum = 0;
    uint32_t x32 = x;
    int i = 0; for (i = 0; i < container->n_runs; i++) {
        uint32_t startpoint = container->runs[i].value;
        uint32_t length = container->runs[i].length;
        uint32_t endpoint = length + startpoint;
        if (x <= endpoint) {
            if (x < startpoint) break;
            return sum + (x32 - startpoint) + 1;
        } else {
            sum += length + 1;
        }
    }
    return sum;
}

#ifdef CROARING_IS_X64

CROARING_TARGET_AVX2
/* Get the cardinality of `run'. Requires an actual computation. */
static inline int _avx2_run_container_cardinality(const run_container_t *run) {
    const int32_t n_runs = run->n_runs;
    const rle16_t *runs = run->runs;

    /* by initializing with n_runs, we omit counting the +1 for each pair. */
    int sum = n_runs;
    int32_t k = 0;
    const int32_t step = sizeof(__m256i) / sizeof(rle16_t);
    if (n_runs > step) {
        __m256i total = _mm256_setzero_si256();
        for (; k + step <= n_runs; k += step) {
            __m256i ymm1 = _mm256_lddqu_si256((const __m256i *)(runs + k));
            __m256i justlengths = _mm256_srli_epi32(ymm1, 16);
            total = _mm256_add_epi32(total, justlengths);
        }
        // a store might be faster than extract?
        uint32_t buffer[sizeof(__m256i) / sizeof(rle16_t)];
        _mm256_storeu_si256((__m256i *)buffer, total);
        sum += (buffer[0] + buffer[1]) + (buffer[2] + buffer[3]) +
               (buffer[4] + buffer[5]) + (buffer[6] + buffer[7]);
    }
    for (; k < n_runs; ++k) {
        sum += runs[k].length;
    }

    return sum;
}

CROARING_UNTARGET_REGION

/* Get the cardinality of `run'. Requires an actual computation. */
static inline int _scalar_run_container_cardinality(const run_container_t *run) {
    const int32_t n_runs = run->n_runs;
    const rle16_t *runs = run->runs;

    /* by initializing with n_runs, we omit counting the +1 for each pair. */
    int sum = n_runs;
    for (int k = 0; k < n_runs; ++k) {
        sum += runs[k].length;
    }

    return sum;
}

static int run_container_cardinality(const run_container_t *run) {
  if( croaring_avx2() ) {
    return _avx2_run_container_cardinality(run);
  } else {
    return _scalar_run_container_cardinality(run);
  }
}
#else

/* Get the cardinality of `run'. Requires an actual computation. */
static int run_container_cardinality(const run_container_t *run) {
    const int32_t n_runs = run->n_runs;
    const rle16_t *runs = run->runs;

    /* by initializing with n_runs, we omit counting the +1 for each pair. */
    int sum = n_runs;
    int k; for (k = 0; k < n_runs; ++k) {
        sum += runs[k].length;
    }

    return sum;
}
#endif


#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/run.c */
/* begin file src/containers/containers.c */


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

extern inline const container_t *container_unwrap_shared(
        const container_t *candidate_shared_container, uint8_t *type);

extern inline container_t *container_mutable_unwrap_shared(
        container_t *candidate_shared_container, uint8_t *type);

extern inline int container_get_cardinality(
        const container_t *c, uint8_t typecode);

extern inline container_t *container_iand(
        container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_ior(
        container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_ixor(
        container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_iandnot(
        container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

static void container_free(container_t *c, uint8_t type) {
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            bitset_container_free(CAST_bitset(c));
            break;
        case ARRAY_CONTAINER_TYPE:
            array_container_free(CAST_array(c));
            break;
        case RUN_CONTAINER_TYPE:
            run_container_free(CAST_run(c));
            break;
        case SHARED_CONTAINER_TYPE:
            shared_container_free(CAST_shared(c));
            break;
        default:
            assert(false);
            __builtin_unreachable();
    }
}

static void container_printf(const container_t *c, uint8_t type) {
    c = container_unwrap_shared(c, &type);
    switch (type) {
        case BITSET_CONTAINER_TYPE:
            bitset_container_printf(const_CAST_bitset(c));
            return;
        case ARRAY_CONTAINER_TYPE:
            array_container_printf(const_CAST_array(c));
            return;
        case RUN_CONTAINER_TYPE:
            run_container_printf(const_CAST_run(c));
            return;
        default:
            __builtin_unreachable();
    }
}

static void container_printf_as_uint32_array(
    const container_t *c, uint8_t typecode,
    uint32_t base
){
    c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            bitset_container_printf_as_uint32_array(
                const_CAST_bitset(c), base);
            return;
        case ARRAY_CONTAINER_TYPE:
            array_container_printf_as_uint32_array(
                const_CAST_array(c), base);
            return;
        case RUN_CONTAINER_TYPE:
            run_container_printf_as_uint32_array(
                const_CAST_run(c), base);
            return;
        default:
            __builtin_unreachable();
    }
}

extern inline bool container_nonzero_cardinality(
        const container_t *c, uint8_t typecode);

extern inline int container_to_uint32_array(
        uint32_t *output,
        const container_t *c, uint8_t typecode,
        uint32_t base);

extern inline container_t *container_add(
        container_t *c,
        uint16_t val,
        uint8_t typecode,  // !!! 2nd arg?
        uint8_t *new_typecode);

extern inline bool container_contains(
        const container_t *c,
        uint16_t val,
        uint8_t typecode);  // !!! 2nd arg?

extern inline container_t *container_and(
        const container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_or(
        const container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_xor(
        const container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

static container_t *get_copy_of_container(
    container_t *c, uint8_t *typecode,
    bool copy_on_write
){
    if (copy_on_write) {
        shared_container_t *shared_container;
        if (*typecode == SHARED_CONTAINER_TYPE) {
            shared_container = CAST_shared(c);
            shared_container->counter += 1;
            return shared_container;
        }
        assert(*typecode != SHARED_CONTAINER_TYPE);

        if ((shared_container = (shared_container_t *)ndpi_malloc(
                 sizeof(shared_container_t))) == NULL) {
            return NULL;
        }

        shared_container->container = c;
        shared_container->typecode = *typecode;

        shared_container->counter = 2;
        *typecode = SHARED_CONTAINER_TYPE;

        return shared_container;
    }  // copy_on_write
    // otherwise, no copy on write...
    const container_t *actual_container = container_unwrap_shared(c, typecode);
    assert(*typecode != SHARED_CONTAINER_TYPE);
    return container_clone(actual_container, *typecode);
}

/**
 * Copies a container, requires a typecode. This allocates new memory, caller
 * is responsible for deallocation.
 */
static container_t *container_clone(const container_t *c, uint8_t typecode) {
    // We do not want to allow cloning of shared containers.
    // c = container_unwrap_shared(c, &typecode);
    switch (typecode) {
        case BITSET_CONTAINER_TYPE:
            return bitset_container_clone(const_CAST_bitset(c));
        case ARRAY_CONTAINER_TYPE:
            return array_container_clone(const_CAST_array(c));
        case RUN_CONTAINER_TYPE:
            return run_container_clone(const_CAST_run(c));
        case SHARED_CONTAINER_TYPE:
            // Shared containers are not cloneable. Are you mixing COW and non-COW bitmaps?
            return NULL;
        default:
            assert(false);
            __builtin_unreachable();
            return NULL;
    }
}

static container_t *shared_container_extract_copy(
    shared_container_t *sc, uint8_t *typecode
){
    assert(sc->counter > 0);
    assert(sc->typecode != SHARED_CONTAINER_TYPE);
    sc->counter--;
    *typecode = sc->typecode;
    container_t *answer;
    if (sc->counter == 0) {
        answer = sc->container;
        sc->container = NULL;  // paranoid
        ndpi_free(sc);
    } else {
        answer = container_clone(sc->container, *typecode);
    }
    assert(*typecode != SHARED_CONTAINER_TYPE);
    return answer;
}

static void shared_container_free(shared_container_t *container) {
    assert(container->counter > 0);
    container->counter--;
    if (container->counter == 0) {
        assert(container->typecode != SHARED_CONTAINER_TYPE);
        container_free(container->container, container->typecode);
        container->container = NULL;  // paranoid
        ndpi_free(container);
    }
}

extern inline container_t *container_not(
        const container_t *c1, uint8_t type1,
        uint8_t *result_type);

extern inline container_t *container_not_range(
        const container_t *c1, uint8_t type1,
        uint32_t range_start, uint32_t range_end,
        uint8_t *result_type);

extern inline container_t *container_inot(
        container_t *c1, uint8_t type1,
        uint8_t *result_type);

extern inline container_t *container_inot_range(
        container_t *c1, uint8_t type1,
        uint32_t range_start, uint32_t range_end,
        uint8_t *result_type);

extern inline container_t *container_range_of_ones(
        uint32_t range_start, uint32_t range_end,
        uint8_t *result_type);

// where are the correponding things for union and intersection??
extern inline container_t *container_lazy_xor(
        const container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_lazy_ixor(
        container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

extern inline container_t *container_andnot(
        const container_t *c1, uint8_t type1,
        const container_t *c2, uint8_t type2,
        uint8_t *result_type);

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/containers.c */
/* begin file src/containers/mixed_andnot.c */
/*
 * mixed_andnot.c.  More methods since operation is not symmetric,
 * except no "wide" andnot , so no lazy options motivated.
 */

#include <assert.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst, a valid array container that could be the same as dst.*/
static void array_bitset_container_andnot(const array_container_t *src_1,
                                   const bitset_container_t *src_2,
                                   array_container_t *dst) {
    // follows Java implementation as of June 2016
    if (dst->capacity < src_1->cardinality) {
        array_container_grow(dst, src_1->cardinality, false);
    }
    int32_t newcard = 0;
    const int32_t origcard = src_1->cardinality;
    int i = 0; for (i = 0; i < origcard; ++i) {
        uint16_t key = src_1->array[i];
        dst->array[newcard] = key;
        newcard += 1 - bitset_container_contains(src_2, key);
    }
    dst->cardinality = newcard;
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * src_1 */

static void array_bitset_container_iandnot(array_container_t *src_1,
                                    const bitset_container_t *src_2) {
    array_bitset_container_andnot(src_1, src_2, src_1);
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst, which does not initially have a valid container.
 * Return true for a bitset result; false for array
 */

static bool bitset_array_container_andnot(
    const bitset_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    // Java did this directly, but we have option of asm or avx
    bitset_container_t *result = bitset_container_create();
    bitset_container_copy(src_1, result);
    result->cardinality =
        (int32_t)bitset_clear_list(result->words, (uint64_t)result->cardinality,
                                   src_2->array, (uint64_t)src_2->cardinality);

    // do required type conversions.
    if (result->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(result);
        bitset_container_free(result);
        return false;
    }
    *dst = result;
    return true;
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_array_container_iandnot(
    bitset_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    *dst = src_1;
    src_1->cardinality =
        (int32_t)bitset_clear_list(src_1->words, (uint64_t)src_1->cardinality,
                                   src_2->array, (uint64_t)src_2->cardinality);

    if (src_1->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(src_1);
        bitset_container_free(src_1);
        return false;  // not bitset
    } else
        return true;
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_andnot(
    const run_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    // follows the Java implementation as of June 2016
    int card = run_container_cardinality(src_1);
    if (card <= DEFAULT_MAX_SIZE) {
        // must be an array
        array_container_t *answer = array_container_create_given_capacity(card);
        answer->cardinality = 0;
        int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
            rle16_t rle = src_1->runs[rlepos];
            int run_value; for (run_value = rle.value; run_value <= rle.value + rle.length;
                 ++run_value) {
                if (!bitset_container_get(src_2, (uint16_t)run_value)) {
                    answer->array[answer->cardinality++] = (uint16_t)run_value;
                }
            }
        }
        *dst = answer;
        return false;
    } else {  // we guess it will be a bitset, though have to check guess when
              // done
        bitset_container_t *answer = bitset_container_clone(src_2);

        uint32_t last_pos = 0;
        int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
            rle16_t rle = src_1->runs[rlepos];

            uint32_t start = rle.value;
            uint32_t end = start + rle.length + 1;
            bitset_reset_range(answer->words, last_pos, start);
            bitset_flip_range(answer->words, start, end);
            last_pos = end;
        }
        bitset_reset_range(answer->words, last_pos, (uint32_t)(1 << 16));

        answer->cardinality = bitset_container_compute_cardinality(answer);

        if (answer->cardinality <= DEFAULT_MAX_SIZE) {
            *dst = array_container_from_bitset(answer);
            bitset_container_free(answer);
            return false;  // not bitset
        }
        *dst = answer;
        return true;  // bitset
    }
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_iandnot(
    run_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    // dummy implementation
    bool ans = run_bitset_container_andnot(src_1, src_2, dst);
    run_container_free(src_1);
    return ans;
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset").  dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool bitset_run_container_andnot(
    const bitset_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    // follows Java implementation
    bitset_container_t *result = bitset_container_create();

    bitset_container_copy(src_1, result);
    int32_t rlepos; for (rlepos = 0; rlepos < src_2->n_runs; ++rlepos) {
        rle16_t rle = src_2->runs[rlepos];
        bitset_reset_range(result->words, rle.value,
                           rle.value + rle.length + UINT32_C(1));
    }
    result->cardinality = bitset_container_compute_cardinality(result);

    if (result->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(result);
        bitset_container_free(result);
        return false;  // not bitset
    }
    *dst = result;
    return true;  // bitset
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_run_container_iandnot(
    bitset_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    *dst = src_1;

    int32_t rlepos; for (rlepos = 0; rlepos < src_2->n_runs; ++rlepos) {
        rle16_t rle = src_2->runs[rlepos];
        bitset_reset_range(src_1->words, rle.value,
                           rle.value + rle.length + UINT32_C(1));
    }
    src_1->cardinality = bitset_container_compute_cardinality(src_1);

    if (src_1->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(src_1);
        bitset_container_free(src_1);
        return false;  // not bitset
    } else
        return true;
}

/* helper. a_out must be a valid array container with adequate capacity.
 * Returns the cardinality of the output container. Partly Based on Java
 * implementation Util.unsignedDifference.
 *
 * TODO: Util.unsignedDifference does not use advanceUntil.  Is it cheaper
 * to avoid advanceUntil?
 */

static int run_array_array_subtract(const run_container_t *rc,
                                    const array_container_t *a_in,
                                    array_container_t *a_out) {
    int out_card = 0;
    int32_t in_array_pos =
        -1;  // since advanceUntil always assumes we start the search AFTER this

    int rlepos; for (rlepos = 0; rlepos < rc->n_runs; rlepos++) {
        int32_t start = rc->runs[rlepos].value;
        int32_t end = start + rc->runs[rlepos].length + 1;

        in_array_pos = advanceUntil(a_in->array, in_array_pos,
                                    a_in->cardinality, (uint16_t)start);

        if (in_array_pos >= a_in->cardinality) {  // run has no items subtracted
            int32_t i; for (i = start; i < end; ++i)
                a_out->array[out_card++] = (uint16_t)i;
        } else {
            uint16_t next_nonincluded = a_in->array[in_array_pos];
            if (next_nonincluded >= end) {
                // another case when run goes unaltered
                int32_t i; for (i = start; i < end; ++i)
                    a_out->array[out_card++] = (uint16_t)i;
                in_array_pos--;  // ensure we see this item again if necessary
            } else {
                int32_t i; for (i = start; i < end; ++i)
                    if (i != next_nonincluded)
                        a_out->array[out_card++] = (uint16_t)i;
                    else  // 0 should ensure  we don't match
                        next_nonincluded =
                            (in_array_pos + 1 >= a_in->cardinality)
                                ? 0
                                : a_in->array[++in_array_pos];
                in_array_pos--;  // see again
            }
        }
    }
    return out_card;
}

/* dst does not indicate a valid container initially.  Eventually it
 * can become any type of container.
 */

static int run_array_container_andnot(
    const run_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    // follows the Java impl as of June 2016

    int card = run_container_cardinality(src_1);
    const int arbitrary_threshold = 32;

    if (card <= arbitrary_threshold) {
        if (src_2->cardinality == 0) {
            *dst = run_container_clone(src_1);
            return RUN_CONTAINER_TYPE;
        }
        // Java's "lazyandNot.toEfficientContainer" thing
        run_container_t *answer = run_container_create_given_capacity(
            card + array_container_cardinality(src_2));

        int rlepos = 0;
        int xrlepos = 0;  // "x" is src_2
        rle16_t rle = src_1->runs[rlepos];
        int32_t start = rle.value;
        int32_t end = start + rle.length + 1;
        int32_t xstart = src_2->array[xrlepos];

        while ((rlepos < src_1->n_runs) && (xrlepos < src_2->cardinality)) {
            if (end <= xstart) {
                // output the first run
                answer->runs[answer->n_runs++] =
                    MAKE_RLE16(start, end - start - 1);
                rlepos++;
                if (rlepos < src_1->n_runs) {
                    start = src_1->runs[rlepos].value;
                    end = start + src_1->runs[rlepos].length + 1;
                }
            } else if (xstart + 1 <= start) {
                // exit the second run
                xrlepos++;
                if (xrlepos < src_2->cardinality) {
                    xstart = src_2->array[xrlepos];
                }
            } else {
                if (start < xstart) {
                    answer->runs[answer->n_runs++] =
                        MAKE_RLE16(start, xstart - start - 1);
                }
                if (xstart + 1 < end) {
                    start = xstart + 1;
                } else {
                    rlepos++;
                    if (rlepos < src_1->n_runs) {
                        start = src_1->runs[rlepos].value;
                        end = start + src_1->runs[rlepos].length + 1;
                    }
                }
            }
        }
        if (rlepos < src_1->n_runs) {
            answer->runs[answer->n_runs++] = MAKE_RLE16(start, end - start - 1);
            rlepos++;
            if (rlepos < src_1->n_runs) {
                memcpy(answer->runs + answer->n_runs, src_1->runs + rlepos,
                       (src_1->n_runs - rlepos) * sizeof(rle16_t));
                answer->n_runs += (src_1->n_runs - rlepos);
            }
        }
        uint8_t return_type;
        *dst = convert_run_to_efficient_container(answer, &return_type);
        if (answer != *dst) run_container_free(answer);
        return return_type;
    }
    // else it's a bitmap or array

    if (card <= DEFAULT_MAX_SIZE) {
        array_container_t *ac = array_container_create_given_capacity(card);
        // nb Java code used a generic iterator-based merge to compute
        // difference
        ac->cardinality = run_array_array_subtract(src_1, src_2, ac);
        *dst = ac;
        return ARRAY_CONTAINER_TYPE;
    }
    bitset_container_t *ans = bitset_container_from_run(src_1);
    bool result_is_bitset = bitset_array_container_iandnot(ans, src_2, dst);
    return (result_is_bitset ? BITSET_CONTAINER_TYPE
                             : ARRAY_CONTAINER_TYPE);
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static int run_array_container_iandnot(
    run_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    // dummy implementation same as June 2016 Java
    int ans = run_array_container_andnot(src_1, src_2, dst);
    run_container_free(src_1);
    return ans;
}

/* dst must be a valid array container, allowed to be src_1 */

static void array_run_container_andnot(const array_container_t *src_1,
                                const run_container_t *src_2,
                                array_container_t *dst) {
    // basically following Java impl as of June 2016
    if (src_1->cardinality > dst->capacity) {
        array_container_grow(dst, src_1->cardinality, false);
    }

    if (src_2->n_runs == 0) {
        memmove(dst->array, src_1->array,
                sizeof(uint16_t) * src_1->cardinality);
        dst->cardinality = src_1->cardinality;
        return;
    }
    int32_t run_start = src_2->runs[0].value;
    int32_t run_end = run_start + src_2->runs[0].length;
    int which_run = 0;

    uint16_t val = 0;
    int dest_card = 0;
    int i = 0; for (i = 0; i < src_1->cardinality; ++i) {
        val = src_1->array[i];
        if (val < run_start)
            dst->array[dest_card++] = val;
        else if (val <= run_end) {
            ;  // omitted item
        } else {
            do {
                if (which_run + 1 < src_2->n_runs) {
                    ++which_run;
                    run_start = src_2->runs[which_run].value;
                    run_end = run_start + src_2->runs[which_run].length;

                } else
                    run_start = run_end = (1 << 16) + 1;
            } while (val > run_end);
            --i;
        }
    }
    dst->cardinality = dest_card;
}

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static void array_run_container_iandnot(array_container_t *src_1,
                                 const run_container_t *src_2) {
    array_run_container_andnot(src_1, src_2, src_1);
}

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int run_run_container_andnot(
    const run_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    run_container_t *ans = run_container_create();
    run_container_andnot(src_1, src_2, ans);
    uint8_t typecode_after;
    *dst = convert_run_to_efficient_container_and_free(ans, &typecode_after);
    return typecode_after;
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static int run_run_container_iandnot(
    run_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    // following Java impl as of June 2016 (dummy)
    int ans = run_run_container_andnot(src_1, src_2, dst);
    run_container_free(src_1);
    return ans;
}

/*
 * dst is a valid array container and may be the same as src_1
 */

static void array_array_container_andnot(const array_container_t *src_1,
                                  const array_container_t *src_2,
                                  array_container_t *dst) {
    array_container_andnot(src_1, src_2, dst);
}

/* inplace array-array andnot will always be able to reuse the space of
 * src_1 */
static void array_array_container_iandnot(array_container_t *src_1,
                                   const array_container_t *src_2) {
    array_container_andnot(src_1, src_2, src_1);
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially). Return value is
 * "dst is a bitset"
 */

static bool bitset_bitset_container_andnot(
    const bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bitset_container_t *ans = bitset_container_create();
    int card = bitset_container_andnot(src_1, src_2, ans);
    if (card <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(ans);
        bitset_container_free(ans);
        return false;  // not bitset
    } else {
        *dst = ans;
        return true;
    }
}

/* Compute the andnot of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_bitset_container_iandnot(
    bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    int card = bitset_container_andnot(src_1, src_2, src_1);
    if (card <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(src_1);
        bitset_container_free(src_1);
        return false;  // not bitset
    } else {
        *dst = src_1;
        return true;
    }
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_andnot.c */
/* begin file src/containers/mixed_negation.c */
/*
 * mixed_negation.c
 *
 */

#include <assert.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

// TODO: make simplified and optimized negation code across
// the full range.

/* Negation across the entire range of the container.
 * Compute the  negation of src  and write the result
 * to *dst. The complement of a
 * sufficiently sparse set will always be dense and a hence a bitmap
' * We assume that dst is pre-allocated and a valid bitset container
 * There can be no in-place version.
 */
static void array_container_negation(const array_container_t *src,
                              bitset_container_t *dst) {
    uint64_t card = UINT64_C(1 << 16);
    bitset_container_set_all(dst);

    if (src->cardinality == 0) {
        return;
    }

    dst->cardinality = (int32_t)bitset_clear_list(dst->words, card, src->array,
                                                  (uint64_t)src->cardinality);
}

/* Negation across the entire range of the container
 * Compute the  negation of src  and write the result
 * to *dst.  A true return value indicates a bitset result,
 * otherwise the result is an array container.
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static bool bitset_container_negation(
    const bitset_container_t *src, container_t **dst
){
    return bitset_container_negation_range(src, 0, (1 << 16), dst);
}

/* inplace version */
/*
 * Same as bitset_container_negation except that if the output is to
 * be a
 * bitset_container_t, then src is modified and no allocation is made.
 * If the output is to be an array_container_t, then caller is responsible
 * to free the container.
 * In all cases, the result is in *dst.
 */
static bool bitset_container_negation_inplace(
    bitset_container_t *src, container_t **dst
){
    return bitset_container_negation_range_inplace(src, 0, (1 << 16), dst);
}

/* Negation across the entire range of container
 * Compute the  negation of src  and write the result
 * to *dst.  Return values are the *_TYPECODES as defined * in containers.h
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static int run_container_negation(const run_container_t *src, container_t **dst) {
    return run_container_negation_range(src, 0, (1 << 16), dst);
}

/*
 * Same as run_container_negation except that if the output is to
 * be a
 * run_container_t, and has the capacity to hold the result,
 * then src is modified and no allocation is made.
 * In all cases, the result is in *dst.
 */
static int run_container_negation_inplace(run_container_t *src, container_t **dst) {
    return run_container_negation_range_inplace(src, 0, (1 << 16), dst);
}

/* Negation across a range of the container.
 * Compute the  negation of src  and write the result
 * to *dst. Returns true if the result is a bitset container
 * and false for an array container.  *dst is not preallocated.
 */
static bool array_container_negation_range(
    const array_container_t *src,
    const int range_start, const int range_end,
    container_t **dst
){
    /* close port of the Java implementation */
    if (range_start >= range_end) {
        *dst = array_container_clone(src);
        return false;
    }

    int32_t start_index =
        binarySearch(src->array, src->cardinality, (uint16_t)range_start);
    if (start_index < 0) start_index = -start_index - 1;

    int32_t last_index =
        binarySearch(src->array, src->cardinality, (uint16_t)(range_end - 1));
    if (last_index < 0) last_index = -last_index - 2;

    const int32_t current_values_in_range = last_index - start_index + 1;
    const int32_t span_to_be_flipped = range_end - range_start;
    const int32_t new_values_in_range =
        span_to_be_flipped - current_values_in_range;
    const int32_t cardinality_change =
        new_values_in_range - current_values_in_range;
    const int32_t new_cardinality = src->cardinality + cardinality_change;

    if (new_cardinality > DEFAULT_MAX_SIZE) {
        bitset_container_t *temp = bitset_container_from_array(src);
        bitset_flip_range(temp->words, (uint32_t)range_start,
                          (uint32_t)range_end);
        temp->cardinality = new_cardinality;
        *dst = temp;
        return true;
    }

    array_container_t *arr =
        array_container_create_given_capacity(new_cardinality);
    *dst = (container_t *)arr;
    if(new_cardinality == 0) {
      arr->cardinality = new_cardinality;
      return false; // we are done.
    }
    // copy stuff before the active area
    memcpy(arr->array, src->array, start_index * sizeof(uint16_t));

    // work on the range
    int32_t out_pos = start_index, in_pos = start_index;
    int32_t val_in_range = range_start;
    for (; val_in_range < range_end && in_pos <= last_index; ++val_in_range) {
        if ((uint16_t)val_in_range != src->array[in_pos]) {
            arr->array[out_pos++] = (uint16_t)val_in_range;
        } else {
            ++in_pos;
        }
    }
    for (; val_in_range < range_end; ++val_in_range)
        arr->array[out_pos++] = (uint16_t)val_in_range;

    // content after the active range
    memcpy(arr->array + out_pos, src->array + (last_index + 1),
           (src->cardinality - (last_index + 1)) * sizeof(uint16_t));
    arr->cardinality = new_cardinality;
    return false;
}

/* Even when the result would fit, it is unclear how to make an
 * inplace version without inefficient copying.
 */

static bool array_container_negation_range_inplace(
    array_container_t *src,
    const int range_start, const int range_end,
    container_t **dst
){
    bool ans = array_container_negation_range(src, range_start, range_end, dst);
    // TODO : try a real inplace version
    array_container_free(src);
    return ans;
}

/* Negation across a range of the container
 * Compute the  negation of src  and write the result
 * to *dst.  A true return value indicates a bitset result,
 * otherwise the result is an array container.
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static bool bitset_container_negation_range(
    const bitset_container_t *src,
    const int range_start, const int range_end,
    container_t **dst
){
    // TODO maybe consider density-based estimate
    // and sometimes build result directly as array, with
    // conversion back to bitset if wrong.  Or determine
    // actual result cardinality, then go directly for the known final cont.

    // keep computation using bitsets as long as possible.
    bitset_container_t *t = bitset_container_clone(src);
    bitset_flip_range(t->words, (uint32_t)range_start, (uint32_t)range_end);
    t->cardinality = bitset_container_compute_cardinality(t);

    if (t->cardinality > DEFAULT_MAX_SIZE) {
        *dst = t;
        return true;
    } else {
        *dst = array_container_from_bitset(t);
        bitset_container_free(t);
        return false;
    }
}

/* inplace version */
/*
 * Same as bitset_container_negation except that if the output is to
 * be a
 * bitset_container_t, then src is modified and no allocation is made.
 * If the output is to be an array_container_t, then caller is responsible
 * to free the container.
 * In all cases, the result is in *dst.
 */
static bool bitset_container_negation_range_inplace(
    bitset_container_t *src,
    const int range_start, const int range_end,
    container_t **dst
){
    bitset_flip_range(src->words, (uint32_t)range_start, (uint32_t)range_end);
    src->cardinality = bitset_container_compute_cardinality(src);
    if (src->cardinality > DEFAULT_MAX_SIZE) {
        *dst = src;
        return true;
    }
    *dst = array_container_from_bitset(src);
    bitset_container_free(src);
    return false;
}

/* Negation across a range of container
 * Compute the  negation of src  and write the result
 * to *dst. Return values are the *_TYPECODES as defined * in containers.h
 *  We assume that dst is not pre-allocated. In
 * case of failure, *dst will be NULL.
 */
static int run_container_negation_range(
    const run_container_t *src,
    const int range_start, const int range_end,
    container_t **dst
){
    uint8_t return_typecode;

    // follows the Java implementation
    if (range_end <= range_start) {
        *dst = run_container_clone(src);
        return RUN_CONTAINER_TYPE;
    }

    run_container_t *ans = run_container_create_given_capacity(
        src->n_runs + 1);  // src->n_runs + 1);
    int k = 0;
    for (; k < src->n_runs && src->runs[k].value < range_start; ++k) {
        ans->runs[k] = src->runs[k];
        ans->n_runs++;
    }

    run_container_smart_append_exclusive(
        ans, (uint16_t)range_start, (uint16_t)(range_end - range_start - 1));

    for (; k < src->n_runs; ++k) {
        run_container_smart_append_exclusive(ans, src->runs[k].value,
                                             src->runs[k].length);
    }

    *dst = convert_run_to_efficient_container(ans, &return_typecode);
    if (return_typecode != RUN_CONTAINER_TYPE) run_container_free(ans);

    return return_typecode;
}

/*
 * Same as run_container_negation except that if the output is to
 * be a
 * run_container_t, and has the capacity to hold the result,
 * then src is modified and no allocation is made.
 * In all cases, the result is in *dst.
 */
static int run_container_negation_range_inplace(
    run_container_t *src,
    const int range_start, const int range_end,
    container_t **dst
){
    uint8_t return_typecode;

    if (range_end <= range_start) {
        *dst = src;
        return RUN_CONTAINER_TYPE;
    }

    // TODO: efficient special case when range is 0 to 65535 inclusive

    if (src->capacity == src->n_runs) {
        // no excess room.  More checking to see if result can fit
        bool last_val_before_range = false;
        bool first_val_in_range = false;
        bool last_val_in_range = false;
        bool first_val_past_range = false;

        if (range_start > 0)
            last_val_before_range =
                run_container_contains(src, (uint16_t)(range_start - 1));
        first_val_in_range = run_container_contains(src, (uint16_t)range_start);

        if (last_val_before_range == first_val_in_range) {
            last_val_in_range =
                run_container_contains(src, (uint16_t)(range_end - 1));
            if (range_end != 0x10000)
                first_val_past_range =
                    run_container_contains(src, (uint16_t)range_end);

            if (last_val_in_range ==
                first_val_past_range) {  // no space for inplace
                int ans = run_container_negation_range(src, range_start,
                                                       range_end, dst);
                run_container_free(src);
                return ans;
            }
        }
    }
    // all other cases: result will fit

    run_container_t *ans = src;
    int my_nbr_runs = src->n_runs;

    ans->n_runs = 0;
    int k = 0;
    for (; (k < my_nbr_runs) && (src->runs[k].value < range_start); ++k) {
        // ans->runs[k] = src->runs[k]; (would be self-copy)
        ans->n_runs++;
    }

    // as with Java implementation, use locals to give self a buffer of depth 1
    rle16_t buffered = MAKE_RLE16(0, 0);
    rle16_t next = buffered;
    if (k < my_nbr_runs) buffered = src->runs[k];

    run_container_smart_append_exclusive(
        ans, (uint16_t)range_start, (uint16_t)(range_end - range_start - 1));

    for (; k < my_nbr_runs; ++k) {
        if (k + 1 < my_nbr_runs) next = src->runs[k + 1];

        run_container_smart_append_exclusive(ans, buffered.value,
                                             buffered.length);
        buffered = next;
    }

    *dst = convert_run_to_efficient_container(ans, &return_typecode);
    if (return_typecode != RUN_CONTAINER_TYPE) run_container_free(ans);

    return return_typecode;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_negation.c */
/* begin file src/containers/mixed_equal.c */

#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

static bool array_container_equal_bitset(const array_container_t* container1,
                                  const bitset_container_t* container2) {
    if (container2->cardinality != BITSET_UNKNOWN_CARDINALITY) {
        if (container2->cardinality != container1->cardinality) {
            return false;
        }
    }
    int32_t pos = 0;
    int32_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i) {
        uint64_t w = container2->words[i];
        while (w != 0) {
            uint64_t t = w & (~w + 1);
            uint16_t r = i * 64 + __builtin_ctzll(w);
            if (pos >= container1->cardinality) {
                return false;
            }
            if (container1->array[pos] != r) {
                return false;
            }
            ++pos;
            w ^= t;
        }
    }
    return (pos == container1->cardinality);
}

static bool run_container_equals_array(const run_container_t* container1,
                                const array_container_t* container2) {
    if (run_container_cardinality(container1) != container2->cardinality)
        return false;
    int32_t pos = 0;
    int i = 0; for (i = 0; i < container1->n_runs; ++i) {
        const uint32_t run_start = container1->runs[i].value;
        const uint32_t le = container1->runs[i].length;

        if (container2->array[pos] != run_start) {
            return false;
        }

        if (container2->array[pos + le] != run_start + le) {
            return false;
        }

        pos += le + 1;
    }
    return true;
}

static bool run_container_equals_bitset(const run_container_t* container1,
                                 const bitset_container_t* container2) {

    int run_card = run_container_cardinality(container1);
    int bitset_card = (container2->cardinality != BITSET_UNKNOWN_CARDINALITY) ?
                      container2->cardinality :
                      bitset_container_compute_cardinality(container2);
    if (bitset_card != run_card) {
        return false;
    }

    int32_t i; for (i = 0; i < container1->n_runs; i++) {
        uint32_t begin = container1->runs[i].value;
        if (container1->runs[i].length) {
            uint32_t end = begin + container1->runs[i].length + 1;
            if (!bitset_container_contains_range(container2, begin, end)) {
                return false;
            }
        } else {
            if (!bitset_container_contains(container2, begin)) {
                return false;
            }
        }
    }

    return true;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_equal.c */
/* begin file src/containers/bitset.c */
/*
 * bitset.c
 *
 */
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

extern inline int bitset_container_cardinality(const bitset_container_t *bitset);
extern inline bool bitset_container_nonzero_cardinality(bitset_container_t *bitset);
extern inline void bitset_container_set(bitset_container_t *bitset, uint16_t pos);
extern inline void bitset_container_unset(bitset_container_t *bitset, uint16_t pos);
extern inline bool bitset_container_get(const bitset_container_t *bitset,
                                        uint16_t pos);
extern inline int32_t bitset_container_serialized_size_in_bytes(void);
extern inline bool bitset_container_add(bitset_container_t *bitset, uint16_t pos);
extern inline bool bitset_container_remove(bitset_container_t *bitset, uint16_t pos);
extern inline bool bitset_container_contains(const bitset_container_t *bitset,
                                             uint16_t pos);

static void bitset_container_clear(bitset_container_t *bitset) {
    memset(bitset->words, 0, sizeof(uint64_t) * BITSET_CONTAINER_SIZE_IN_WORDS);
    bitset->cardinality = 0;
}

static void bitset_container_set_all(bitset_container_t *bitset) {
    memset(bitset->words, INT64_C(-1),
           sizeof(uint64_t) * BITSET_CONTAINER_SIZE_IN_WORDS);
    bitset->cardinality = (1 << 16);
}



/* Create a new bitset. Return NULL in case of failure. */
static bitset_container_t *bitset_container_create(void) {
    bitset_container_t *bitset =
        (bitset_container_t *)ndpi_malloc(sizeof(bitset_container_t));

    if (!bitset) {
        return NULL;
    }
    // sizeof(__m256i) == 32
    bitset->words = (uint64_t *)roaring_bitmap_aligned_malloc(
        32, sizeof(uint64_t) * BITSET_CONTAINER_SIZE_IN_WORDS);
    if (!bitset->words) {
        ndpi_free(bitset);
        return NULL;
    }
    bitset_container_clear(bitset);
    return bitset;
}

/* Copy one container into another. We assume that they are distinct. */
static void bitset_container_copy(const bitset_container_t *source,
                           bitset_container_t *dest) {
    dest->cardinality = source->cardinality;
    memcpy(dest->words, source->words,
           sizeof(uint64_t) * BITSET_CONTAINER_SIZE_IN_WORDS);
}

static void bitset_container_add_from_range(bitset_container_t *bitset, uint32_t min,
                                     uint32_t max, uint16_t step) {
    if (step == 0) return;   // refuse to crash
    if ((64 % step) == 0) {  // step divides 64
        uint64_t mask = 0;   // construct the repeated mask
        uint32_t value; for (value = (min % step); value < 64; value += step) {
            mask |= ((uint64_t)1 << value);
        }
        uint32_t firstword = min / 64;
        uint32_t endword = (max - 1) / 64;
        bitset->cardinality = (max - min + step - 1) / step;
        if (firstword == endword) {
            bitset->words[firstword] |=
                mask & (((~UINT64_C(0)) << (min % 64)) &
                        ((~UINT64_C(0)) >> ((~max + 1) % 64)));
            return;
        }
        bitset->words[firstword] = mask & ((~UINT64_C(0)) << (min % 64));
        uint32_t i; for (i = firstword + 1; i < endword; i++)
            bitset->words[i] = mask;
        bitset->words[endword] = mask & ((~UINT64_C(0)) >> ((~max + 1) % 64));
    } else {
        uint32_t value; for (value = min; value < max; value += step) {
            bitset_container_add(bitset, value);
        }
    }
}

/* Free memory. */
static void bitset_container_free(bitset_container_t *bitset) {
    if(bitset->words != NULL) {// Jon Strabala reports that some tools complain otherwise
      roaring_bitmap_aligned_free(bitset->words);
      bitset->words = NULL; // pedantic
    }
    ndpi_free(bitset);
}

/* duplicate container. */
static bitset_container_t *bitset_container_clone(const bitset_container_t *src) {
    bitset_container_t *bitset =
        (bitset_container_t *)ndpi_malloc(sizeof(bitset_container_t));

    if (!bitset) {
        return NULL;
    }
    // sizeof(__m256i) == 32
    bitset->words = (uint64_t *)roaring_bitmap_aligned_malloc(
        32, sizeof(uint64_t) * BITSET_CONTAINER_SIZE_IN_WORDS);
    if (!bitset->words) {
        ndpi_free(bitset);
        return NULL;
    }
    bitset->cardinality = src->cardinality;
    memcpy(bitset->words, src->words,
           sizeof(uint64_t) * BITSET_CONTAINER_SIZE_IN_WORDS);
    return bitset;
}

static void bitset_container_set_range(bitset_container_t *bitset, uint32_t begin,
                                uint32_t end) {
    bitset_set_range(bitset->words, begin, end);
    bitset->cardinality =
        bitset_container_compute_cardinality(bitset);  // could be smarter
}


static bool bitset_container_intersect(const bitset_container_t *src_1,
                                  const bitset_container_t *src_2) {
	// could vectorize, but this is probably already quite fast in practice
    const uint64_t * __restrict__ words_1 = src_1->words;
    const uint64_t * __restrict__ words_2 = src_2->words;
	int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i ++) {
        if((words_1[i] & words_2[i]) != 0) return true;
    }
    return false;
}


#ifdef CROARING_IS_X64
#ifndef WORDS_IN_AVX2_REG
#define WORDS_IN_AVX2_REG sizeof(__m256i) / sizeof(uint64_t)
#endif
/* Get the number of bits set (force computation) */
static inline int _scalar_bitset_container_compute_cardinality(const bitset_container_t *bitset) {
  const uint64_t *words = bitset->words;
  int32_t sum = 0;
  int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 4) {
          sum += hamming(words[i]);
          sum += hamming(words[i + 1]);
          sum += hamming(words[i + 2]);
          sum += hamming(words[i + 3]);
  }
  return sum;
}
/* Get the number of bits set (force computation) */
static int bitset_container_compute_cardinality(const bitset_container_t *bitset) {
    if( croaring_avx2() ) {
      return (int) avx2_harley_seal_popcount256(
        (const __m256i *)bitset->words,
        BITSET_CONTAINER_SIZE_IN_WORDS / (WORDS_IN_AVX2_REG));
    } else {
      return _scalar_bitset_container_compute_cardinality(bitset);

    }
}

#elif defined(USENEON)
static int bitset_container_compute_cardinality(const bitset_container_t *bitset) {
    uint16x8_t n0 = vdupq_n_u16(0);
    uint16x8_t n1 = vdupq_n_u16(0);
    uint16x8_t n2 = vdupq_n_u16(0);
    uint16x8_t n3 = vdupq_n_u16(0);
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 8) {
        uint64x2_t c0 = vld1q_u64(&bitset->words[i + 0]);
        n0 = vaddq_u16(n0, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c0))));
        uint64x2_t c1 = vld1q_u64(&bitset->words[i + 2]);
        n1 = vaddq_u16(n1, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c1))));
        uint64x2_t c2 = vld1q_u64(&bitset->words[i + 4]);
        n2 = vaddq_u16(n2, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c2))));
        uint64x2_t c3 = vld1q_u64(&bitset->words[i + 6]);
        n3 = vaddq_u16(n3, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c3))));
    }
    uint64x2_t n = vdupq_n_u64(0);
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n0)));
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n1)));
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n2)));
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n3)));
    return vgetq_lane_u64(n, 0) + vgetq_lane_u64(n, 1);
}

#else // CROARING_IS_X64

/* Get the number of bits set (force computation) */
static int bitset_container_compute_cardinality(const bitset_container_t *bitset) {
    const uint64_t *words = bitset->words;
    int32_t sum = 0;
    int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 4) {
        sum += hamming(words[i]);
        sum += hamming(words[i + 1]);
        sum += hamming(words[i + 2]);
        sum += hamming(words[i + 3]);
    }
    return sum;
}

#endif // CROARING_IS_X64

#ifdef CROARING_IS_X64

#define BITSET_CONTAINER_FN_REPEAT 8
#ifndef WORDS_IN_AVX2_REG
#define WORDS_IN_AVX2_REG sizeof(__m256i) / sizeof(uint64_t)
#endif // WORDS_IN_AVX2_REG
#define LOOP_SIZE                    \
    BITSET_CONTAINER_SIZE_IN_WORDS / \
        ((WORDS_IN_AVX2_REG)*BITSET_CONTAINER_FN_REPEAT)

/* Computes a binary operation (eg union) on bitset1 and bitset2 and write the
   result to bitsetout */
// clang-format off
#define AVX_BITSET_CONTAINER_FN1(before, opname, opsymbol, avx_intrinsic,               \
                                neon_intrinsic, after)                                \
  static inline int _avx2_bitset_container_##opname##_nocard(                                \
      const bitset_container_t *src_1, const bitset_container_t *src_2,        \
      bitset_container_t *dst) {                                               \
    const uint8_t *__restrict__ words_1 = (const uint8_t *)src_1->words;       \
    const uint8_t *__restrict__ words_2 = (const uint8_t *)src_2->words;       \
    /* not using the blocking optimization for some reason*/                   \
    uint8_t *out = (uint8_t *)dst->words;                                      \
    const int innerloop = 8;                                                   \
    size_t i; for (i = 0;                                                         \
         i < BITSET_CONTAINER_SIZE_IN_WORDS / (WORDS_IN_AVX2_REG);             \
         i += innerloop) {                                                     \
      __m256i A1, A2, AO;                                                      \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1));                     \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2));                     \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)out, AO);                                 \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 32));                \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 32));                \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 32), AO);                          \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 64));                \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 64));                \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 64), AO);                          \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 96));                \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 96));                \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 96), AO);                          \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 128));               \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 128));               \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 128), AO);                         \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 160));               \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 160));               \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 160), AO);                         \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 192));               \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 192));               \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 192), AO);                         \
      A1 = _mm256_lddqu_si256((const __m256i *)(words_1 + 224));               \
      A2 = _mm256_lddqu_si256((const __m256i *)(words_2 + 224));               \
      AO = avx_intrinsic(A2, A1);                                              \
      _mm256_storeu_si256((__m256i *)(out + 224), AO);                         \
      out += 256;                                                              \
      words_1 += 256;                                                          \
      words_2 += 256;                                                          \
    }                                                                          \
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;                             \
    return dst->cardinality;                                                   \
  }

#define AVX_BITSET_CONTAINER_FN2(before, opname, opsymbol, avx_intrinsic,               \
                                neon_intrinsic, after)                                \
  /* next, a version that updates cardinality*/                                \
  static inline int _avx2_bitset_container_##opname(const bitset_container_t *src_1,         \
                                      const bitset_container_t *src_2,         \
                                      bitset_container_t *dst) {               \
    const __m256i *__restrict__ words_1 = (const __m256i *)src_1->words;       \
    const __m256i *__restrict__ words_2 = (const __m256i *)src_2->words;       \
    __m256i *out = (__m256i *)dst->words;                                      \
    dst->cardinality = (int32_t)avx2_harley_seal_popcount256andstore_##opname( \
        words_2, words_1, out,                                                 \
        BITSET_CONTAINER_SIZE_IN_WORDS / (WORDS_IN_AVX2_REG));                 \
    return dst->cardinality;                                                   \
  }                                                                            \

#define AVX_BITSET_CONTAINER_FN3(before, opname, opsymbol, avx_intrinsic,               \
                                neon_intrinsic, after)                                \
  /* next, a version that just computes the cardinality*/                      \
  static inline int _avx2_bitset_container_##opname##_justcard(                              \
      const bitset_container_t *src_1, const bitset_container_t *src_2) {      \
    const __m256i *__restrict__ data1 = (const __m256i *)src_1->words;         \
    const __m256i *__restrict__ data2 = (const __m256i *)src_2->words;         \
    return (int)avx2_harley_seal_popcount256_##opname(                         \
        data2, data1, BITSET_CONTAINER_SIZE_IN_WORDS / (WORDS_IN_AVX2_REG));   \
  }


// we duplicate the function because other containers use the "or" term, makes API more consistent
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN1(CROARING_TARGET_AVX2, or,    |, _mm256_or_si256, vorrq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN1(CROARING_TARGET_AVX2, union, |, _mm256_or_si256, vorrq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

// we duplicate the function because other containers use the "intersection" term, makes API more consistent
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN1(CROARING_TARGET_AVX2, and,          &, _mm256_and_si256, vandq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN1(CROARING_TARGET_AVX2, intersection, &, _mm256_and_si256, vandq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN1(CROARING_TARGET_AVX2, xor,    ^,  _mm256_xor_si256,    veorq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN1(CROARING_TARGET_AVX2, andnot, &~, _mm256_andnot_si256, vbicq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

// we duplicate the function because other containers use the "or" term, makes API more consistent
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN2(CROARING_TARGET_AVX2, or,    |, _mm256_or_si256, vorrq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN2(CROARING_TARGET_AVX2, union, |, _mm256_or_si256, vorrq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

// we duplicate the function because other containers use the "intersection" term, makes API more consistent
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN2(CROARING_TARGET_AVX2, and,          &, _mm256_and_si256, vandq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN2(CROARING_TARGET_AVX2, intersection, &, _mm256_and_si256, vandq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN2(CROARING_TARGET_AVX2, xor,    ^,  _mm256_xor_si256,    veorq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN2(CROARING_TARGET_AVX2, andnot, &~, _mm256_andnot_si256, vbicq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

// we duplicate the function because other containers use the "or" term, makes API more consistent
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN3(CROARING_TARGET_AVX2, or,    |, _mm256_or_si256, vorrq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN3(CROARING_TARGET_AVX2, union, |, _mm256_or_si256, vorrq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

// we duplicate the function because other containers use the "intersection" term, makes API more consistent
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN3(CROARING_TARGET_AVX2, and,          &, _mm256_and_si256, vandq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN3(CROARING_TARGET_AVX2, intersection, &, _mm256_and_si256, vandq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION

CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN3(CROARING_TARGET_AVX2, xor,    ^,  _mm256_xor_si256,    veorq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION
CROARING_TARGET_AVX2
AVX_BITSET_CONTAINER_FN3(CROARING_TARGET_AVX2, andnot, &~, _mm256_andnot_si256, vbicq_u64, CROARING_UNTARGET_REGION)
CROARING_UNTARGET_REGION


#define SCALAR_BITSET_CONTAINER_FN(opname, opsymbol, avx_intrinsic,            \
                                   neon_intrinsic)                             \
  static inline int _scalar_bitset_container_##opname(const bitset_container_t *src_1,       \
                                        const bitset_container_t *src_2,       \
                                        bitset_container_t *dst) {             \
    const uint64_t *__restrict__ words_1 = src_1->words;                       \
    const uint64_t *__restrict__ words_2 = src_2->words;                       \
    uint64_t *out = dst->words;                                                \
    int32_t sum = 0;                                                           \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 2) {           \
      const uint64_t word_1 = (words_1[i])opsymbol(words_2[i]),                \
                     word_2 = (words_1[i + 1]) opsymbol(words_2[i + 1]);       \
      out[i] = word_1;                                                         \
      out[i + 1] = word_2;                                                     \
      sum += hamming(word_1);                                                  \
      sum += hamming(word_2);                                                  \
    }                                                                          \
    dst->cardinality = sum;                                                    \
    return dst->cardinality;                                                   \
  }                                                                            \
  static inline int _scalar_bitset_container_##opname##_nocard(                              \
      const bitset_container_t *src_1, const bitset_container_t *src_2,        \
      bitset_container_t *dst) {                                               \
    const uint64_t *__restrict__ words_1 = src_1->words;                       \
    const uint64_t *__restrict__ words_2 = src_2->words;                       \
    uint64_t *out = dst->words;                                                \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i++) {              \
      out[i] = (words_1[i])opsymbol(words_2[i]);                               \
    }                                                                          \
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;                             \
    return dst->cardinality;                                                   \
  }                                                                            \
  static inline int _scalar_bitset_container_##opname##_justcard(                            \
      const bitset_container_t *src_1, const bitset_container_t *src_2) {      \
    const uint64_t *__restrict__ words_1 = src_1->words;                       \
    const uint64_t *__restrict__ words_2 = src_2->words;                       \
    int32_t sum = 0;                                                           \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 2) {           \
      const uint64_t word_1 = (words_1[i])opsymbol(words_2[i]),                \
                     word_2 = (words_1[i + 1]) opsymbol(words_2[i + 1]);       \
      sum += hamming(word_1);                                                  \
      sum += hamming(word_2);                                                  \
    }                                                                          \
    return sum;                                                                \
  }

// we duplicate the function because other containers use the "or" term, makes API more consistent
SCALAR_BITSET_CONTAINER_FN(or,    |, _mm256_or_si256, vorrq_u64)
SCALAR_BITSET_CONTAINER_FN(union, |, _mm256_or_si256, vorrq_u64)

// we duplicate the function because other containers use the "intersection" term, makes API more consistent
SCALAR_BITSET_CONTAINER_FN(and,          &, _mm256_and_si256, vandq_u64)
SCALAR_BITSET_CONTAINER_FN(intersection, &, _mm256_and_si256, vandq_u64)

SCALAR_BITSET_CONTAINER_FN(xor,    ^,  _mm256_xor_si256,    veorq_u64)
SCALAR_BITSET_CONTAINER_FN(andnot, &~, _mm256_andnot_si256, vbicq_u64)


#define BITSET_CONTAINER_FN(opname, opsymbol, avx_intrinsic, neon_intrinsic)   \
  static int bitset_container_##opname(const bitset_container_t *src_1,               \
                                const bitset_container_t *src_2,               \
                                bitset_container_t *dst) {                     \
    if ( croaring_avx2() ) {                                                       \
      return _avx2_bitset_container_##opname(src_1, src_2, dst);               \
    } else {                                                                   \
      return _scalar_bitset_container_##opname(src_1, src_2, dst);             \
    }                                                                          \
  }                                                                            \
  static int bitset_container_##opname##_nocard(const bitset_container_t *src_1,      \
                                         const bitset_container_t *src_2,      \
                                         bitset_container_t *dst) {            \
    if ( croaring_avx2() ) {                                                       \
      return _avx2_bitset_container_##opname##_nocard(src_1, src_2, dst);      \
    } else {                                                                   \
      return _scalar_bitset_container_##opname##_nocard(src_1, src_2, dst);    \
    }                                                                          \
  }                                                                            \
  static int bitset_container_##opname##_justcard(const bitset_container_t *src_1,    \
                                           const bitset_container_t *src_2) {  \
    if ((croaring_detect_supported_architectures() & CROARING_AVX2) ==         \
        CROARING_AVX2) {                                                       \
      return _avx2_bitset_container_##opname##_justcard(src_1, src_2);         \
    } else {                                                                   \
      return _scalar_bitset_container_##opname##_justcard(src_1, src_2);       \
    }                                                                          \
  }



#elif defined(USENEON)

#define BITSET_CONTAINER_FN(opname, opsymbol, avx_intrinsic, neon_intrinsic)  \
static int bitset_container_##opname(const bitset_container_t *src_1,                \
                              const bitset_container_t *src_2,                \
                              bitset_container_t *dst) {                      \
    const uint64_t * __restrict__ words_1 = src_1->words;                     \
    const uint64_t * __restrict__ words_2 = src_2->words;                     \
    uint64_t *out = dst->words;                                               \
    uint16x8_t n0 = vdupq_n_u16(0);                                           \
    uint16x8_t n1 = vdupq_n_u16(0);                                           \
    uint16x8_t n2 = vdupq_n_u16(0);                                           \
    uint16x8_t n3 = vdupq_n_u16(0);                                           \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 8) {          \
        uint64x2_t c0 = neon_intrinsic(vld1q_u64(&words_1[i + 0]),            \
                                       vld1q_u64(&words_2[i + 0]));           \
        n0 = vaddq_u16(n0, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c0))));   \
        vst1q_u64(&out[i + 0], c0);                                           \
        uint64x2_t c1 = neon_intrinsic(vld1q_u64(&words_1[i + 2]),            \
                                       vld1q_u64(&words_2[i + 2]));           \
        n1 = vaddq_u16(n1, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c1))));   \
        vst1q_u64(&out[i + 2], c1);                                           \
        uint64x2_t c2 = neon_intrinsic(vld1q_u64(&words_1[i + 4]),            \
                                       vld1q_u64(&words_2[i + 4]));           \
        n2 = vaddq_u16(n2, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c2))));   \
        vst1q_u64(&out[i + 4], c2);                                           \
        uint64x2_t c3 = neon_intrinsic(vld1q_u64(&words_1[i + 6]),            \
                                       vld1q_u64(&words_2[i + 6]));           \
        n3 = vaddq_u16(n3, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c3))));   \
        vst1q_u64(&out[i + 6], c3);                                           \
    }                                                                         \
    uint64x2_t n = vdupq_n_u64(0);                                            \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n0)));                           \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n1)));                           \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n2)));                           \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n3)));                           \
    dst->cardinality = vgetq_lane_u64(n, 0) + vgetq_lane_u64(n, 1);           \
    return dst->cardinality;                                                  \
}                                                                             \
static int bitset_container_##opname##_nocard(const bitset_container_t *src_1,       \
                                       const bitset_container_t *src_2,       \
                                             bitset_container_t *dst) {       \
    const uint64_t * __restrict__ words_1 = src_1->words;                     \
    const uint64_t * __restrict__ words_2 = src_2->words;                     \
    uint64_t *out = dst->words;                                               \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 8) {          \
        vst1q_u64(&out[i + 0], neon_intrinsic(vld1q_u64(&words_1[i + 0]),     \
                                              vld1q_u64(&words_2[i + 0])));   \
        vst1q_u64(&out[i + 2], neon_intrinsic(vld1q_u64(&words_1[i + 2]),     \
                                              vld1q_u64(&words_2[i + 2])));   \
        vst1q_u64(&out[i + 4], neon_intrinsic(vld1q_u64(&words_1[i + 4]),     \
                                              vld1q_u64(&words_2[i + 4])));   \
        vst1q_u64(&out[i + 6], neon_intrinsic(vld1q_u64(&words_1[i + 6]),     \
                                              vld1q_u64(&words_2[i + 6])));   \
    }                                                                         \
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;                            \
    return dst->cardinality;                                                  \
}                                                                             \
static int bitset_container_##opname##_justcard(const bitset_container_t *src_1,     \
                                         const bitset_container_t *src_2) {   \
    const uint64_t * __restrict__ words_1 = src_1->words;                     \
    const uint64_t * __restrict__ words_2 = src_2->words;                     \
    uint16x8_t n0 = vdupq_n_u16(0);                                           \
    uint16x8_t n1 = vdupq_n_u16(0);                                           \
    uint16x8_t n2 = vdupq_n_u16(0);                                           \
    uint16x8_t n3 = vdupq_n_u16(0);                                           \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 8) {          \
        uint64x2_t c0 = neon_intrinsic(vld1q_u64(&words_1[i + 0]),            \
                                       vld1q_u64(&words_2[i + 0]));           \
        n0 = vaddq_u16(n0, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c0))));   \
        uint64x2_t c1 = neon_intrinsic(vld1q_u64(&words_1[i + 2]),            \
                                       vld1q_u64(&words_2[i + 2]));           \
        n1 = vaddq_u16(n1, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c1))));   \
        uint64x2_t c2 = neon_intrinsic(vld1q_u64(&words_1[i + 4]),            \
                                       vld1q_u64(&words_2[i + 4]));           \
        n2 = vaddq_u16(n2, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c2))));   \
        uint64x2_t c3 = neon_intrinsic(vld1q_u64(&words_1[i + 6]),            \
                                       vld1q_u64(&words_2[i + 6]));           \
        n3 = vaddq_u16(n3, vpaddlq_u8(vcntq_u8(vreinterpretq_u8_u64(c3))));   \
    }                                                                         \
    uint64x2_t n = vdupq_n_u64(0);                                            \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n0)));                           \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n1)));                           \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n2)));                           \
    n = vaddq_u64(n, vpaddlq_u32(vpaddlq_u16(n3)));                           \
    return vgetq_lane_u64(n, 0) + vgetq_lane_u64(n, 1);                       \
}

#else

#define BITSET_CONTAINER_FN(opname, opsymbol, avx_intrinsic, neon_intrinsic)  \
static int bitset_container_##opname(const bitset_container_t *src_1,            \
                              const bitset_container_t *src_2,            \
                              bitset_container_t *dst) {                  \
    const uint64_t * __restrict__ words_1 = src_1->words;                 \
    const uint64_t * __restrict__ words_2 = src_2->words;                 \
    uint64_t *out = dst->words;                                           \
    int32_t sum = 0;                                                      \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 2) {      \
        const uint64_t word_1 = (words_1[i])opsymbol(words_2[i]),         \
                       word_2 = (words_1[i + 1])opsymbol(words_2[i + 1]); \
        out[i] = word_1;                                                  \
        out[i + 1] = word_2;                                              \
        sum += hamming(word_1);                                    \
        sum += hamming(word_2);                                    \
    }                                                                     \
    dst->cardinality = sum;                                               \
    return dst->cardinality;                                              \
}                                                                         \
static int bitset_container_##opname##_nocard(const bitset_container_t *src_1,   \
                                       const bitset_container_t *src_2,   \
                                       bitset_container_t *dst) {         \
    const uint64_t * __restrict__ words_1 = src_1->words;                 \
    const uint64_t * __restrict__ words_2 = src_2->words;                 \
    uint64_t *out = dst->words;                                           \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i++) {         \
        out[i] = (words_1[i])opsymbol(words_2[i]);                        \
    }                                                                     \
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;                        \
    return dst->cardinality;                                              \
}                                                                         \
static int bitset_container_##opname##_justcard(const bitset_container_t *src_1, \
                              const bitset_container_t *src_2) {          \
    const uint64_t * __restrict__ words_1 = src_1->words;                 \
    const uint64_t * __restrict__ words_2 = src_2->words;                 \
    int32_t sum = 0;                                                      \
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 2) {      \
        const uint64_t word_1 = (words_1[i])opsymbol(words_2[i]),         \
                       word_2 = (words_1[i + 1])opsymbol(words_2[i + 1]); \
        sum += hamming(word_1);                                    \
        sum += hamming(word_2);                                    \
    }                                                                     \
    return sum;                                                           \
}

#endif // CROARING_IS_X64

// we duplicate the function because other containers use the "or" term, makes API more consistent
BITSET_CONTAINER_FN(or,    |, _mm256_or_si256, vorrq_u64)
BITSET_CONTAINER_FN(union, |, _mm256_or_si256, vorrq_u64)

// we duplicate the function because other containers use the "intersection" term, makes API more consistent
BITSET_CONTAINER_FN(and,          &, _mm256_and_si256, vandq_u64)
BITSET_CONTAINER_FN(intersection, &, _mm256_and_si256, vandq_u64)

BITSET_CONTAINER_FN(xor,    ^,  _mm256_xor_si256,    veorq_u64)
BITSET_CONTAINER_FN(andnot, &~, _mm256_andnot_si256, vbicq_u64)
// clang-format On


static int bitset_container_to_uint32_array(
    uint32_t *out,
    const bitset_container_t *bc,
    uint32_t base
){
#ifdef CROARING_IS_X64
    if(( croaring_avx2() ) &&  (bc->cardinality >= 8192))  // heuristic
		return (int) bitset_extract_setbits_avx2(bc->words,
                BITSET_CONTAINER_SIZE_IN_WORDS, out, bc->cardinality, base);
	else
		return (int) bitset_extract_setbits(bc->words,
                BITSET_CONTAINER_SIZE_IN_WORDS, out, base);
#else
	return (int) bitset_extract_setbits(bc->words,
                BITSET_CONTAINER_SIZE_IN_WORDS, out, base);
#endif
}

/*
 * Print this container using printf (useful for debugging).
 */
static void bitset_container_printf(const bitset_container_t * v) {
	printf("{");
	uint32_t base = 0;
	bool iamfirst = true;// TODO: rework so that this is not necessary yet still readable
	int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i) {
		uint64_t w = v->words[i];
		while (w != 0) {
			uint64_t t = w & (~w + 1);
			int r = __builtin_ctzll(w);
			if(iamfirst) {// predicted to be false
				printf("%u",base + r);
				iamfirst = false;
			} else {
				printf(",%u",base + r);
			}
			w ^= t;
		}
		base += 64;
	}
	printf("}");
}


/*
 * Print this container using printf as a comma-separated list of 32-bit integers starting at base.
 */
static void bitset_container_printf_as_uint32_array(const bitset_container_t * v, uint32_t base) {
	bool iamfirst = true;// TODO: rework so that this is not necessary yet still readable
	int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i) {
		uint64_t w = v->words[i];
		while (w != 0) {
			uint64_t t = w & (~w + 1);
			int r = __builtin_ctzll(w);
			if(iamfirst) {// predicted to be false
				printf("%u", r + base);
				iamfirst = false;
			} else {
				printf(",%u",r + base);
			}
			w ^= t;
		}
		base += 64;
	}
}


// TODO: use the fast lower bound, also
static int bitset_container_number_of_runs(bitset_container_t *bc) {
  int num_runs = 0;
  uint64_t next_word = bc->words[0];

  int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS-1; ++i) {
    uint64_t word = next_word;
    next_word = bc->words[i+1];
    num_runs += hamming((~word) & (word << 1)) + ( (word >> 63) & ~next_word);
  }

  uint64_t word = next_word;
  num_runs += hamming((~word) & (word << 1));
  if((word & 0x8000000000000000ULL) != 0)
    num_runs++;
  return num_runs;
}


static int32_t bitset_container_write(const bitset_container_t *container,
                                  char *buf) {
	memcpy(buf, container->words, BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t));
	return bitset_container_size_in_bytes(container);
}


static int32_t bitset_container_read(int32_t cardinality, bitset_container_t *container,
		const char *buf)  {
	container->cardinality = cardinality;
	memcpy(container->words, buf, BITSET_CONTAINER_SIZE_IN_WORDS * sizeof(uint64_t));
	return bitset_container_size_in_bytes(container);
}

static bool bitset_container_iterate(const bitset_container_t *cont, uint32_t base, roaring_iterator iterator, void *ptr) {
  int32_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i ) {
    uint64_t w = cont->words[i];
    while (w != 0) {
      uint64_t t = w & (~w + 1);
      int r = __builtin_ctzll(w);
      if(!iterator(r + base, ptr)) return false;
      w ^= t;
    }
    base += 64;
  }
  return true;
}

static bool bitset_container_iterate64(const bitset_container_t *cont, uint32_t base, roaring_iterator64 iterator, uint64_t high_bits, void *ptr) {
  int32_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i ) {
    uint64_t w = cont->words[i];
    while (w != 0) {
      uint64_t t = w & (~w + 1);
      int r = __builtin_ctzll(w);
      if(!iterator(high_bits | (uint64_t)(r + base), ptr)) return false;
      w ^= t;
    }
    base += 64;
  }
  return true;
}

#ifdef CROARING_IS_X64
CROARING_TARGET_AVX2
static inline bool _avx2_bitset_container_equals(const bitset_container_t *container1, const bitset_container_t *container2) {
    const __m256i *ptr1 = (const __m256i*)container1->words;
    const __m256i *ptr2 = (const __m256i*)container2->words;
    size_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS*sizeof(uint64_t)/32; i++) {
      __m256i r1 = _mm256_load_si256(ptr1+i);
      __m256i r2 = _mm256_load_si256(ptr2+i);
      int mask = _mm256_movemask_epi8(_mm256_cmpeq_epi8(r1, r2));
      if ((uint32_t)mask != UINT32_MAX) {
          return false;
      }
  }
	return true;
}
CROARING_UNTARGET_REGION
#endif // CROARING_IS_X64

static bool bitset_container_equals(const bitset_container_t *container1, const bitset_container_t *container2) {
  if((container1->cardinality != BITSET_UNKNOWN_CARDINALITY) && (container2->cardinality != BITSET_UNKNOWN_CARDINALITY)) {
    if(container1->cardinality != container2->cardinality) {
      return false;
    }
    if (container1->cardinality == INT32_C(0x10000)) {
      return true;
    }
  }
#ifdef CROARING_IS_X64
  if( croaring_avx2() ) {
    return _avx2_bitset_container_equals(container1, container2);
  }
#endif
  return memcmp(container1->words,
                container2->words,
                BITSET_CONTAINER_SIZE_IN_WORDS*sizeof(uint64_t)) == 0;
}

static bool bitset_container_is_subset(const bitset_container_t *container1,
                          const bitset_container_t *container2) {
    if((container1->cardinality != BITSET_UNKNOWN_CARDINALITY) && (container2->cardinality != BITSET_UNKNOWN_CARDINALITY)) {
        if(container1->cardinality > container2->cardinality) {
            return false;
        }
    }
    int32_t i ; for(i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i ) {
		if((container1->words[i] & container2->words[i]) != container1->words[i]) {
			return false;
		}
	}
	return true;
}

static bool bitset_container_select(const bitset_container_t *container, uint32_t *start_rank, uint32_t rank, uint32_t *element) {
    int card = bitset_container_cardinality(container);
    if(rank >= *start_rank + card) {
        *start_rank += card;
        return false;
    }
    const uint64_t *words = container->words;
    int32_t size;
    int i = 0; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; i += 1) {
        size = hamming(words[i]);
        if(rank <= *start_rank + size) {
            uint64_t w = container->words[i];
            uint16_t base = i*64;
            while (w != 0) {
                uint64_t t = w & (~w + 1);
                int r = __builtin_ctzll(w);
                if(*start_rank == rank) {
                    *element = r+base;
                    return true;
                }
                w ^= t;
                *start_rank += 1;
            }
        }
        else
            *start_rank += size;
    }
    assert(false);
    __builtin_unreachable();
}


/* Returns the smallest value (assumes not empty) */
static uint16_t bitset_container_minimum(const bitset_container_t *container) {
  int32_t i; for (i = 0; i < BITSET_CONTAINER_SIZE_IN_WORDS; ++i ) {
    uint64_t w = container->words[i];
    if (w != 0) {
      int r = __builtin_ctzll(w);
      return r + i * 64;
    }
  }
  return UINT16_MAX;
}

/* Returns the largest value (assumes not empty) */
static uint16_t bitset_container_maximum(const bitset_container_t *container) {
  int32_t i; for (i = BITSET_CONTAINER_SIZE_IN_WORDS - 1; i > 0; --i ) {
    uint64_t w = container->words[i];
    if (w != 0) {
      int r = __builtin_clzll(w);
      return i * 64 + 63  - r;
    }
  }
  return 0;
}

/* Returns the number of values equal or smaller than x */
static int bitset_container_rank(const bitset_container_t *container, uint16_t x) {
  // credit: aqrit
  int sum = 0;
  int i = 0, end;
  for (end = x / 64; i < end; i++){
    sum += hamming(container->words[i]);
  }
  uint64_t lastword = container->words[i];
  uint64_t lastpos = UINT64_C(1) << (x % 64);
  uint64_t mask = lastpos + lastpos - 1; // smear right
  sum += hamming(lastword & mask);
  return sum;
}

/* Returns the index of the first value equal or larger than x, or -1 */
static int bitset_container_index_equalorlarger(const bitset_container_t *container, uint16_t x) {
  uint32_t x32 = x;
  uint32_t k = x32 / 64;
  uint64_t word = container->words[k];
  const int diff = x32 - k * 64; // in [0,64)
  word = (word >> diff) << diff; // a mask is faster, but we don't care
  while(word == 0) {
    k++;
    if(k == BITSET_CONTAINER_SIZE_IN_WORDS) return -1;
    word = container->words[k];
  }
  return k * 64 + __builtin_ctzll(word);
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/bitset.c */
/* begin file src/containers/mixed_intersection.c */
/*
 * mixed_intersection.c
 *
 */


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the intersection of src_1 and src_2 and write the result to
 * dst.  */
static void array_bitset_container_intersection(const array_container_t *src_1,
                                         const bitset_container_t *src_2,
                                         array_container_t *dst) {
    if (dst->capacity < src_1->cardinality) {
        array_container_grow(dst, src_1->cardinality, false);
    }
    int32_t newcard = 0;  // dst could be src_1
    const int32_t origcard = src_1->cardinality;
    int i = 0; for (i = 0; i < origcard; ++i) {
        uint16_t key = src_1->array[i];
        // this branchless approach is much faster...
        dst->array[newcard] = key;
        newcard += bitset_container_contains(src_2, key);
        /**
         * we could do it this way instead...
         * if (bitset_container_contains(src_2, key)) {
         * dst->array[newcard++] = key;
         * }
         * but if the result is unpredictible, the processor generates
         * many mispredicted branches.
         * Difference can be huge (from 3 cycles when predictible all the way
         * to 16 cycles when unpredictible.
         * See
         * https://github.com/lemire/Code-used-on-Daniel-Lemire-s-blog/blob/master/extra/bitset/c/arraybitsetintersection.c
         */
    }
    dst->cardinality = newcard;
}

/* Compute the size of the intersection of src_1 and src_2. */
static int array_bitset_container_intersection_cardinality(
    const array_container_t *src_1, const bitset_container_t *src_2) {
    int32_t newcard = 0;
    const int32_t origcard = src_1->cardinality;
    int i = 0; for (i = 0; i < origcard; ++i) {
        uint16_t key = src_1->array[i];
        newcard += bitset_container_contains(src_2, key);
    }
    return newcard;
}


static bool array_bitset_container_intersect(const array_container_t *src_1,
                                         const bitset_container_t *src_2) {
	const int32_t origcard = src_1->cardinality;
	int i = 0; for (i = 0; i < origcard; ++i) {
	        uint16_t key = src_1->array[i];
	        if(bitset_container_contains(src_2, key)) return true;
	}
	return false;
}

/* Compute the intersection of src_1 and src_2 and write the result to
 * dst. It is allowed for dst to be equal to src_1. We assume that dst is a
 * valid container. */
static void array_run_container_intersection(const array_container_t *src_1,
                                      const run_container_t *src_2,
                                      array_container_t *dst) {
    if (run_container_is_full(src_2)) {
        if (dst != src_1) array_container_copy(src_1, dst);
        return;
    }
    if (dst->capacity < src_1->cardinality) {
        array_container_grow(dst, src_1->cardinality, false);
    }
    if (src_2->n_runs == 0) {
        return;
    }
    int32_t rlepos = 0;
    int32_t arraypos = 0;
    rle16_t rle = src_2->runs[rlepos];
    int32_t newcard = 0;
    while (arraypos < src_1->cardinality) {
        const uint16_t arrayval = src_1->array[arraypos];
        while (rle.value + rle.length <
               arrayval) {  // this will frequently be false
            ++rlepos;
            if (rlepos == src_2->n_runs) {
                dst->cardinality = newcard;
                return;  // we are done
            }
            rle = src_2->runs[rlepos];
        }
        if (rle.value > arrayval) {
            arraypos = advanceUntil(src_1->array, arraypos, src_1->cardinality,
                                    rle.value);
        } else {
            dst->array[newcard] = arrayval;
            newcard++;
            arraypos++;
        }
    }
    dst->cardinality = newcard;
}

/* Compute the intersection of src_1 and src_2 and write the result to
 * *dst. If the result is true then the result is a bitset_container_t
 * otherwise is a array_container_t. If *dst ==  src_2, an in-place processing
 * is attempted.*/
static bool run_bitset_container_intersection(
    const run_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    if (run_container_is_full(src_1)) {
        if (*dst != src_2) *dst = bitset_container_clone(src_2);
        return true;
    }
    int32_t card = run_container_cardinality(src_1);
    if (card <= DEFAULT_MAX_SIZE) {
        // result can only be an array (assuming that we never make a
        // RunContainer)
        if (card > src_2->cardinality) {
            card = src_2->cardinality;
        }
        array_container_t *answer = array_container_create_given_capacity(card);
        *dst = answer;
        if (*dst == NULL) {
            return false;
        }
        int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
            rle16_t rle = src_1->runs[rlepos];
            uint32_t endofrun = (uint32_t)rle.value + rle.length, runValue;
            for (runValue = rle.value; runValue <= endofrun;
                 ++runValue) {
                answer->array[answer->cardinality] = (uint16_t)runValue;
                answer->cardinality +=
                    bitset_container_contains(src_2, runValue);
            }
        }
        return false;
    }
    if (*dst == src_2) {  // we attempt in-place
        bitset_container_t *answer = CAST_bitset(*dst);
        uint32_t start = 0;
        int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
            const rle16_t rle = src_1->runs[rlepos];
            uint32_t end = rle.value;
            bitset_reset_range(src_2->words, start, end);

            start = end + rle.length + 1;
        }
        bitset_reset_range(src_2->words, start, UINT32_C(1) << 16);
        answer->cardinality = bitset_container_compute_cardinality(answer);
        if (src_2->cardinality > DEFAULT_MAX_SIZE) {
            return true;
        } else {
            array_container_t *newanswer = array_container_from_bitset(src_2);
            if (newanswer == NULL) {
                *dst = NULL;
                return false;
            }
            *dst = newanswer;
            return false;
        }
    } else {  // no inplace
        // we expect the answer to be a bitmap (if we are lucky)
        bitset_container_t *answer = bitset_container_clone(src_2);

        *dst = answer;
        if (answer == NULL) {
            return true;
        }
        uint32_t start = 0;
        int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
            const rle16_t rle = src_1->runs[rlepos];
            uint32_t end = rle.value;
            bitset_reset_range(answer->words, start, end);
            start = end + rle.length + 1;
        }
        bitset_reset_range(answer->words, start, UINT32_C(1) << 16);
        answer->cardinality = bitset_container_compute_cardinality(answer);

        if (answer->cardinality > DEFAULT_MAX_SIZE) {
            return true;
        } else {
            array_container_t *newanswer = array_container_from_bitset(answer);
            bitset_container_free(CAST_bitset(*dst));
            if (newanswer == NULL) {
                *dst = NULL;
                return false;
            }
            *dst = newanswer;
            return false;
        }
    }
}

/* Compute the size of the intersection between src_1 and src_2 . */
static int array_run_container_intersection_cardinality(const array_container_t *src_1,
                                                 const run_container_t *src_2) {
    if (run_container_is_full(src_2)) {
        return src_1->cardinality;
    }
    if (src_2->n_runs == 0) {
        return 0;
    }
    int32_t rlepos = 0;
    int32_t arraypos = 0;
    rle16_t rle = src_2->runs[rlepos];
    int32_t newcard = 0;
    while (arraypos < src_1->cardinality) {
        const uint16_t arrayval = src_1->array[arraypos];
        while (rle.value + rle.length <
               arrayval) {  // this will frequently be false
            ++rlepos;
            if (rlepos == src_2->n_runs) {
                return newcard;  // we are done
            }
            rle = src_2->runs[rlepos];
        }
        if (rle.value > arrayval) {
            arraypos = advanceUntil(src_1->array, arraypos, src_1->cardinality,
                                    rle.value);
        } else {
            newcard++;
            arraypos++;
        }
    }
    return newcard;
}

/* Compute the intersection  between src_1 and src_2
 **/
static int run_bitset_container_intersection_cardinality(
    const run_container_t *src_1, const bitset_container_t *src_2) {
    if (run_container_is_full(src_1)) {
        return bitset_container_cardinality(src_2);
    }
    int answer = 0;
    int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
        rle16_t rle = src_1->runs[rlepos];
        answer +=
            bitset_lenrange_cardinality(src_2->words, rle.value, rle.length);
    }
    return answer;
}


static bool array_run_container_intersect(const array_container_t *src_1,
                                      const run_container_t *src_2) {
	if( run_container_is_full(src_2) ) {
	    return !array_container_empty(src_1);
	}
	if (src_2->n_runs == 0) {
        return false;
    }
    int32_t rlepos = 0;
    int32_t arraypos = 0;
    rle16_t rle = src_2->runs[rlepos];
    while (arraypos < src_1->cardinality) {
        const uint16_t arrayval = src_1->array[arraypos];
        while (rle.value + rle.length <
               arrayval) {  // this will frequently be false
            ++rlepos;
            if (rlepos == src_2->n_runs) {
                return false;  // we are done
            }
            rle = src_2->runs[rlepos];
        }
        if (rle.value > arrayval) {
            arraypos = advanceUntil(src_1->array, arraypos, src_1->cardinality,
                                    rle.value);
        } else {
            return true;
        }
    }
    return false;
}

/* Compute the intersection  between src_1 and src_2
 **/
static bool run_bitset_container_intersect(const run_container_t *src_1,
                                       const bitset_container_t *src_2) {
	   if( run_container_is_full(src_1) ) {
		   return !bitset_container_empty(src_2);
	   }
       int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
           rle16_t rle = src_1->runs[rlepos];
           if(!bitset_lenrange_empty(src_2->words, rle.value,rle.length)) return true;
       }
       return false;
}

/*
 * Compute the intersection between src_1 and src_2 and write the result
 * to *dst. If the return function is true, the result is a bitset_container_t
 * otherwise is a array_container_t.
 */
static bool bitset_bitset_container_intersection(
    const bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    const int newCardinality = bitset_container_and_justcard(src_1, src_2);
    if (newCardinality > DEFAULT_MAX_SIZE) {
        *dst = bitset_container_create();
        if (*dst != NULL) {
            bitset_container_and_nocard(src_1, src_2, CAST_bitset(*dst));
            CAST_bitset(*dst)->cardinality = newCardinality;
        }
        return true;  // it is a bitset
    }
    *dst = array_container_create_given_capacity(newCardinality);
    if (*dst != NULL) {
        CAST_array(*dst)->cardinality = newCardinality;
        bitset_extract_intersection_setbits_uint16(
            src_1->words, src_2->words, BITSET_CONTAINER_SIZE_IN_WORDS,
            CAST_array(*dst)->array, 0);
    }
    return false;  // not a bitset
}

static bool bitset_bitset_container_intersection_inplace(
    bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    const int newCardinality = bitset_container_and_justcard(src_1, src_2);
    if (newCardinality > DEFAULT_MAX_SIZE) {
        *dst = src_1;
        bitset_container_and_nocard(src_1, src_2, src_1);
        CAST_bitset(*dst)->cardinality = newCardinality;
        return true;  // it is a bitset
    }
    *dst = array_container_create_given_capacity(newCardinality);
    if (*dst != NULL) {
        CAST_array(*dst)->cardinality = newCardinality;
        bitset_extract_intersection_setbits_uint16(
            src_1->words, src_2->words, BITSET_CONTAINER_SIZE_IN_WORDS,
            CAST_array(*dst)->array, 0);
    }
    return false;  // not a bitset
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_intersection.c */
/* begin file src/containers/mixed_subset.c */

#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

static bool array_container_is_subset_bitset(const array_container_t* container1,
                                      const bitset_container_t* container2) {
    if (container2->cardinality != BITSET_UNKNOWN_CARDINALITY) {
        if (container2->cardinality < container1->cardinality) {
            return false;
        }
    }
    int i = 0; for (i = 0; i < container1->cardinality; ++i) {
        if (!bitset_container_contains(container2, container1->array[i])) {
            return false;
        }
    }
    return true;
}

static bool run_container_is_subset_array(const run_container_t* container1,
                                   const array_container_t* container2) {
    if (run_container_cardinality(container1) > container2->cardinality)
        return false;
    int32_t start_pos = -1, stop_pos = -1;
    int i = 0; for (i = 0; i < container1->n_runs; ++i) {
        int32_t start = container1->runs[i].value;
        int32_t stop = start + container1->runs[i].length;
        start_pos = advanceUntil(container2->array, stop_pos,
                                 container2->cardinality, start);
        stop_pos = advanceUntil(container2->array, stop_pos,
                                container2->cardinality, stop);
        if (start_pos == container2->cardinality) {
            return false;
        } else if (stop_pos - start_pos != stop - start ||
                   container2->array[start_pos] != start ||
                   container2->array[stop_pos] != stop) {
            return false;
        }
    }
    return true;
}

static bool array_container_is_subset_run(const array_container_t* container1,
                                   const run_container_t* container2) {
    if (container1->cardinality > run_container_cardinality(container2))
        return false;
    int i_array = 0, i_run = 0;
    while (i_array < container1->cardinality && i_run < container2->n_runs) {
        uint32_t start = container2->runs[i_run].value;
        uint32_t stop = start + container2->runs[i_run].length;
        if (container1->array[i_array] < start) {
            return false;
        } else if (container1->array[i_array] > stop) {
            i_run++;
        } else {  // the value of the array is in the run
            i_array++;
        }
    }
    if (i_array == container1->cardinality) {
        return true;
    } else {
        return false;
    }
}

static bool run_container_is_subset_bitset(const run_container_t* container1,
                                    const bitset_container_t* container2) {
    // todo: this code could be much faster
    if (container2->cardinality != BITSET_UNKNOWN_CARDINALITY) {
        if (container2->cardinality < run_container_cardinality(container1)) {
            return false;
        }
    } else {
        int32_t card = bitset_container_compute_cardinality(
            container2);  // modify container2?
        if (card < run_container_cardinality(container1)) {
            return false;
        }
    }
    int i = 0; for (i = 0; i < container1->n_runs; ++i) {
        uint32_t run_start = container1->runs[i].value;
        uint32_t le = container1->runs[i].length;
        uint32_t j; for (j = run_start; j <= run_start + le; ++j) {
            if (!bitset_container_contains(container2, j)) {
                return false;
            }
        }
    }
    return true;
}

static bool bitset_container_is_subset_run(const bitset_container_t* container1,
                                    const run_container_t* container2) {
    // todo: this code could be much faster
    if (container1->cardinality != BITSET_UNKNOWN_CARDINALITY) {
        if (container1->cardinality > run_container_cardinality(container2)) {
            return false;
        }
    }
    int32_t i_bitset = 0, i_run = 0;
    while (i_bitset < BITSET_CONTAINER_SIZE_IN_WORDS &&
           i_run < container2->n_runs) {
        uint64_t w = container1->words[i_bitset];
        while (w != 0 && i_run < container2->n_runs) {
            uint32_t start = container2->runs[i_run].value;
            uint32_t stop = start + container2->runs[i_run].length;
            uint64_t t = w & (~w + 1);
            uint16_t r = i_bitset * 64 + __builtin_ctzll(w);
            if (r < start) {
                return false;
            } else if (r > stop) {
                i_run++;
                continue;
            } else {
                w ^= t;
            }
        }
        if (w == 0) {
            i_bitset++;
        } else {
            return false;
        }
    }
    if (i_bitset < BITSET_CONTAINER_SIZE_IN_WORDS) {
        // terminated iterating on the run containers, check that rest of bitset
        // is empty
        for (; i_bitset < BITSET_CONTAINER_SIZE_IN_WORDS; i_bitset++) {
            if (container1->words[i_bitset] != 0) {
                return false;
            }
        }
    }
    return true;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_subset.c */
/* begin file src/containers/mixed_xor.c */
/*
 * mixed_xor.c
 */

#include <assert.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

/* Compute the xor of src_1 and src_2 and write the result to
 * dst (which has no container initially).
 * Result is true iff dst is a bitset  */
static bool array_bitset_container_xor(
    const array_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bitset_container_t *result = bitset_container_create();
    bitset_container_copy(src_2, result);
    result->cardinality = (int32_t)bitset_flip_list_withcard(
        result->words, result->cardinality, src_1->array, src_1->cardinality);

    // do required type conversions.
    if (result->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(result);
        bitset_container_free(result);
        return false;  // not bitset
    }
    *dst = result;
    return true;  // bitset
}

/* Compute the xor of src_1 and src_2 and write the result to
 * dst. It is allowed for src_2 to be dst.  This version does not
 * update the cardinality of dst (it is set to BITSET_UNKNOWN_CARDINALITY).
 */

static void array_bitset_container_lazy_xor(const array_container_t *src_1,
                                     const bitset_container_t *src_2,
                                     bitset_container_t *dst) {
    if (src_2 != dst) bitset_container_copy(src_2, dst);
    bitset_flip_list(dst->words, src_1->array, src_1->cardinality);
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;
}

/* Compute the xor of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_xor(
    const run_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bitset_container_t *result = bitset_container_create();

    bitset_container_copy(src_2, result);
    int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
        rle16_t rle = src_1->runs[rlepos];
        bitset_flip_range(result->words, rle.value,
                          rle.value + rle.length + UINT32_C(1));
    }
    result->cardinality = bitset_container_compute_cardinality(result);

    if (result->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(result);
        bitset_container_free(result);
        return false;  // not bitset
    }
    *dst = result;
    return true;  // bitset
}

/* lazy xor.  Dst is initialized and may be equal to src_2.
 *  Result is left as a bitset container, even if actual
 *  cardinality would dictate an array container.
 */

static void run_bitset_container_lazy_xor(const run_container_t *src_1,
                                   const bitset_container_t *src_2,
                                   bitset_container_t *dst) {
    if (src_2 != dst) bitset_container_copy(src_2, dst);
    int32_t rlepos; for (rlepos = 0; rlepos < src_1->n_runs; ++rlepos) {
        rle16_t rle = src_1->runs[rlepos];
        bitset_flip_range(dst->words, rle.value,
                          rle.value + rle.length + UINT32_C(1));
    }
    dst->cardinality = BITSET_UNKNOWN_CARDINALITY;
}

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int array_run_container_xor(
    const array_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    // semi following Java XOR implementation as of May 2016
    // the C OR implementation works quite differently and can return a run
    // container
    // TODO could optimize for full run containers.

    // use of lazy following Java impl.
    const int arbitrary_threshold = 32;
    if (src_1->cardinality < arbitrary_threshold) {
        run_container_t *ans = run_container_create();
        array_run_container_lazy_xor(src_1, src_2, ans);  // keeps runs.
        uint8_t typecode_after;
        *dst =
            convert_run_to_efficient_container_and_free(ans, &typecode_after);
        return typecode_after;
    }

    int card = run_container_cardinality(src_2);
    if (card <= DEFAULT_MAX_SIZE) {
        // Java implementation works with the array, xoring the run elements via
        // iterator
        array_container_t *temp = array_container_from_run(src_2);
        bool ret_is_bitset = array_array_container_xor(temp, src_1, dst);
        array_container_free(temp);
        return ret_is_bitset ? BITSET_CONTAINER_TYPE
                             : ARRAY_CONTAINER_TYPE;

    } else {  // guess that it will end up as a bitset
        bitset_container_t *result = bitset_container_from_run(src_2);
        bool is_bitset = bitset_array_container_ixor(result, src_1, dst);
        // any necessary type conversion has been done by the ixor
        int retval = (is_bitset ? BITSET_CONTAINER_TYPE
                                : ARRAY_CONTAINER_TYPE);
        return retval;
    }
}

/* Dst is a valid run container. (Can it be src_2? Let's say not.)
 * Leaves result as run container, even if other options are
 * smaller.
 */

static void array_run_container_lazy_xor(const array_container_t *src_1,
                                  const run_container_t *src_2,
                                  run_container_t *dst) {
    run_container_grow(dst, src_1->cardinality + src_2->n_runs, false);
    int32_t rlepos = 0;
    int32_t arraypos = 0;
    dst->n_runs = 0;

    while ((rlepos < src_2->n_runs) && (arraypos < src_1->cardinality)) {
        if (src_2->runs[rlepos].value <= src_1->array[arraypos]) {
            run_container_smart_append_exclusive(dst, src_2->runs[rlepos].value,
                                                 src_2->runs[rlepos].length);
            rlepos++;
        } else {
            run_container_smart_append_exclusive(dst, src_1->array[arraypos],
                                                 0);
            arraypos++;
        }
    }
    while (arraypos < src_1->cardinality) {
        run_container_smart_append_exclusive(dst, src_1->array[arraypos], 0);
        arraypos++;
    }
    while (rlepos < src_2->n_runs) {
        run_container_smart_append_exclusive(dst, src_2->runs[rlepos].value,
                                             src_2->runs[rlepos].length);
        rlepos++;
    }
}

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int run_run_container_xor(
    const run_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    run_container_t *ans = run_container_create();
    run_container_xor(src_1, src_2, ans);
    uint8_t typecode_after;
    *dst = convert_run_to_efficient_container_and_free(ans, &typecode_after);
    return typecode_after;
}

/*
 * Java implementation (as of May 2016) for array_run, run_run
 * and  bitset_run don't do anything different for inplace.
 * Could adopt the mixed_union.c approach instead (ie, using
 * smart_append_exclusive)
 *
 */

static bool array_array_container_xor(
    const array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int totalCardinality =
        src_1->cardinality + src_2->cardinality;  // upper bound
    if (totalCardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_create_given_capacity(totalCardinality);
        array_container_xor(src_1, src_2, CAST_array(*dst));
        return false;  // not a bitset
    }
    *dst = bitset_container_from_array(src_1);
    bool returnval = true;  // expect a bitset
    bitset_container_t *ourbitset = CAST_bitset(*dst);
    ourbitset->cardinality = (uint32_t)bitset_flip_list_withcard(
        ourbitset->words, src_1->cardinality, src_2->array, src_2->cardinality);
    if (ourbitset->cardinality <= DEFAULT_MAX_SIZE) {
        // need to convert!
        *dst = array_container_from_bitset(ourbitset);
        bitset_container_free(ourbitset);
        returnval = false;  // not going to be a bitset
    }

    return returnval;
}

static bool array_array_container_lazy_xor(
    const array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int totalCardinality = src_1->cardinality + src_2->cardinality;
    // upper bound, but probably poor estimate for xor
    if (totalCardinality <= ARRAY_LAZY_LOWERBOUND) {
        *dst = array_container_create_given_capacity(totalCardinality);
        if (*dst != NULL)
            array_container_xor(src_1, src_2, CAST_array(*dst));
        return false;  // not a bitset
    }
    *dst = bitset_container_from_array(src_1);
    bool returnval = true;  // expect a bitset (maybe, for XOR??)
    if (*dst != NULL) {
        bitset_container_t *ourbitset = CAST_bitset(*dst);
        bitset_flip_list(ourbitset->words, src_2->array, src_2->cardinality);
        ourbitset->cardinality = BITSET_UNKNOWN_CARDINALITY;
    }
    return returnval;
}

/* Compute the xor of src_1 and src_2 and write the result to
 * dst (which has no container initially). Return value is
 * "dst is a bitset"
 */

static bool bitset_bitset_container_xor(
    const bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bitset_container_t *ans = bitset_container_create();
    int card = bitset_container_xor(src_1, src_2, ans);
    if (card <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(ans);
        bitset_container_free(ans);
        return false;  // not bitset
    } else {
        *dst = ans;
        return true;
    }
}

/* Compute the xor of src_1 and src_2 and write the result to
 * dst (which has no container initially).  It will modify src_1
 * to be dst if the result is a bitset.  Otherwise, it will
 * free src_1 and dst will be a new array container.  In both
 * cases, the caller is responsible for deallocating dst.
 * Returns true iff dst is a bitset  */

static bool bitset_array_container_ixor(
    bitset_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    *dst = src_1;
    src_1->cardinality = (uint32_t)bitset_flip_list_withcard(
        src_1->words, src_1->cardinality, src_2->array, src_2->cardinality);

    if (src_1->cardinality <= DEFAULT_MAX_SIZE) {
        *dst = array_container_from_bitset(src_1);
        bitset_container_free(src_1);
        return false;  // not bitset
    } else
        return true;
}

/* a bunch of in-place, some of which may not *really* be inplace.
 * TODO: write actual inplace routine if efficiency warrants it
 * Anything inplace with a bitset is a good candidate
 */

static bool bitset_bitset_container_ixor(
    bitset_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bool ans = bitset_bitset_container_xor(src_1, src_2, dst);
    bitset_container_free(src_1);
    return ans;
}

static bool array_bitset_container_ixor(
    array_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bool ans = array_bitset_container_xor(src_1, src_2, dst);
    array_container_free(src_1);
    return ans;
}

/* Compute the xor of src_1 and src_2 and write the result to
 * dst. Result may be either a bitset or an array container
 * (returns "result is bitset"). dst does not initially have
 * any container, but becomes either a bitset container (return
 * result true) or an array container.
 */

static bool run_bitset_container_ixor(
    run_container_t *src_1, const bitset_container_t *src_2,
    container_t **dst
){
    bool ans = run_bitset_container_xor(src_1, src_2, dst);
    run_container_free(src_1);
    return ans;
}

static bool bitset_run_container_ixor(
    bitset_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    bool ans = run_bitset_container_xor(src_2, src_1, dst);
    bitset_container_free(src_1);
    return ans;
}

/* dst does not indicate a valid container initially.  Eventually it
 * can become any kind of container.
 */

static int array_run_container_ixor(
    array_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    int ans = array_run_container_xor(src_1, src_2, dst);
    array_container_free(src_1);
    return ans;
}

static int run_array_container_ixor(
    run_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    int ans = array_run_container_xor(src_2, src_1, dst);
    run_container_free(src_1);
    return ans;
}

static bool array_array_container_ixor(
    array_container_t *src_1, const array_container_t *src_2,
    container_t **dst
){
    bool ans = array_array_container_xor(src_1, src_2, dst);
    array_container_free(src_1);
    return ans;
}

static int run_run_container_ixor(
    run_container_t *src_1, const run_container_t *src_2,
    container_t **dst
){
    int ans = run_run_container_xor(src_1, src_2, dst);
    run_container_free(src_1);
    return ans;
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/containers/mixed_xor.c */
/* begin file src/bitset_util.c */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#ifdef __cplusplus
extern "C" { namespace roaring { namespace internal {
#endif

#ifdef CROARING_IS_X64
static uint8_t lengthTable[256] = {
    0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4,
    2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5,
    3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6,
    4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7,
    4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8};
#endif

#ifdef CROARING_IS_X64
ALIGNED(32)
static uint32_t vecDecodeTable[256][8] = {
    {0, 0, 0, 0, 0, 0, 0, 0}, /* 0x00 (00000000) */
    {1, 0, 0, 0, 0, 0, 0, 0}, /* 0x01 (00000001) */
    {2, 0, 0, 0, 0, 0, 0, 0}, /* 0x02 (00000010) */
    {1, 2, 0, 0, 0, 0, 0, 0}, /* 0x03 (00000011) */
    {3, 0, 0, 0, 0, 0, 0, 0}, /* 0x04 (00000100) */
    {1, 3, 0, 0, 0, 0, 0, 0}, /* 0x05 (00000101) */
    {2, 3, 0, 0, 0, 0, 0, 0}, /* 0x06 (00000110) */
    {1, 2, 3, 0, 0, 0, 0, 0}, /* 0x07 (00000111) */
    {4, 0, 0, 0, 0, 0, 0, 0}, /* 0x08 (00001000) */
    {1, 4, 0, 0, 0, 0, 0, 0}, /* 0x09 (00001001) */
    {2, 4, 0, 0, 0, 0, 0, 0}, /* 0x0A (00001010) */
    {1, 2, 4, 0, 0, 0, 0, 0}, /* 0x0B (00001011) */
    {3, 4, 0, 0, 0, 0, 0, 0}, /* 0x0C (00001100) */
    {1, 3, 4, 0, 0, 0, 0, 0}, /* 0x0D (00001101) */
    {2, 3, 4, 0, 0, 0, 0, 0}, /* 0x0E (00001110) */
    {1, 2, 3, 4, 0, 0, 0, 0}, /* 0x0F (00001111) */
    {5, 0, 0, 0, 0, 0, 0, 0}, /* 0x10 (00010000) */
    {1, 5, 0, 0, 0, 0, 0, 0}, /* 0x11 (00010001) */
    {2, 5, 0, 0, 0, 0, 0, 0}, /* 0x12 (00010010) */
    {1, 2, 5, 0, 0, 0, 0, 0}, /* 0x13 (00010011) */
    {3, 5, 0, 0, 0, 0, 0, 0}, /* 0x14 (00010100) */
    {1, 3, 5, 0, 0, 0, 0, 0}, /* 0x15 (00010101) */
    {2, 3, 5, 0, 0, 0, 0, 0}, /* 0x16 (00010110) */
    {1, 2, 3, 5, 0, 0, 0, 0}, /* 0x17 (00010111) */
    {4, 5, 0, 0, 0, 0, 0, 0}, /* 0x18 (00011000) */
    {1, 4, 5, 0, 0, 0, 0, 0}, /* 0x19 (00011001) */
    {2, 4, 5, 0, 0, 0, 0, 0}, /* 0x1A (00011010) */
    {1, 2, 4, 5, 0, 0, 0, 0}, /* 0x1B (00011011) */
    {3, 4, 5, 0, 0, 0, 0, 0}, /* 0x1C (00011100) */
    {1, 3, 4, 5, 0, 0, 0, 0}, /* 0x1D (00011101) */
    {2, 3, 4, 5, 0, 0, 0, 0}, /* 0x1E (00011110) */
    {1, 2, 3, 4, 5, 0, 0, 0}, /* 0x1F (00011111) */
    {6, 0, 0, 0, 0, 0, 0, 0}, /* 0x20 (00100000) */
    {1, 6, 0, 0, 0, 0, 0, 0}, /* 0x21 (00100001) */
    {2, 6, 0, 0, 0, 0, 0, 0}, /* 0x22 (00100010) */
    {1, 2, 6, 0, 0, 0, 0, 0}, /* 0x23 (00100011) */
    {3, 6, 0, 0, 0, 0, 0, 0}, /* 0x24 (00100100) */
    {1, 3, 6, 0, 0, 0, 0, 0}, /* 0x25 (00100101) */
    {2, 3, 6, 0, 0, 0, 0, 0}, /* 0x26 (00100110) */
    {1, 2, 3, 6, 0, 0, 0, 0}, /* 0x27 (00100111) */
    {4, 6, 0, 0, 0, 0, 0, 0}, /* 0x28 (00101000) */
    {1, 4, 6, 0, 0, 0, 0, 0}, /* 0x29 (00101001) */
    {2, 4, 6, 0, 0, 0, 0, 0}, /* 0x2A (00101010) */
    {1, 2, 4, 6, 0, 0, 0, 0}, /* 0x2B (00101011) */
    {3, 4, 6, 0, 0, 0, 0, 0}, /* 0x2C (00101100) */
    {1, 3, 4, 6, 0, 0, 0, 0}, /* 0x2D (00101101) */
    {2, 3, 4, 6, 0, 0, 0, 0}, /* 0x2E (00101110) */
    {1, 2, 3, 4, 6, 0, 0, 0}, /* 0x2F (00101111) */
    {5, 6, 0, 0, 0, 0, 0, 0}, /* 0x30 (00110000) */
    {1, 5, 6, 0, 0, 0, 0, 0}, /* 0x31 (00110001) */
    {2, 5, 6, 0, 0, 0, 0, 0}, /* 0x32 (00110010) */
    {1, 2, 5, 6, 0, 0, 0, 0}, /* 0x33 (00110011) */
    {3, 5, 6, 0, 0, 0, 0, 0}, /* 0x34 (00110100) */
    {1, 3, 5, 6, 0, 0, 0, 0}, /* 0x35 (00110101) */
    {2, 3, 5, 6, 0, 0, 0, 0}, /* 0x36 (00110110) */
    {1, 2, 3, 5, 6, 0, 0, 0}, /* 0x37 (00110111) */
    {4, 5, 6, 0, 0, 0, 0, 0}, /* 0x38 (00111000) */
    {1, 4, 5, 6, 0, 0, 0, 0}, /* 0x39 (00111001) */
    {2, 4, 5, 6, 0, 0, 0, 0}, /* 0x3A (00111010) */
    {1, 2, 4, 5, 6, 0, 0, 0}, /* 0x3B (00111011) */
    {3, 4, 5, 6, 0, 0, 0, 0}, /* 0x3C (00111100) */
    {1, 3, 4, 5, 6, 0, 0, 0}, /* 0x3D (00111101) */
    {2, 3, 4, 5, 6, 0, 0, 0}, /* 0x3E (00111110) */
    {1, 2, 3, 4, 5, 6, 0, 0}, /* 0x3F (00111111) */
    {7, 0, 0, 0, 0, 0, 0, 0}, /* 0x40 (01000000) */
    {1, 7, 0, 0, 0, 0, 0, 0}, /* 0x41 (01000001) */
    {2, 7, 0, 0, 0, 0, 0, 0}, /* 0x42 (01000010) */
    {1, 2, 7, 0, 0, 0, 0, 0}, /* 0x43 (01000011) */
    {3, 7, 0, 0, 0, 0, 0, 0}, /* 0x44 (01000100) */
    {1, 3, 7, 0, 0, 0, 0, 0}, /* 0x45 (01000101) */
    {2, 3, 7, 0, 0, 0, 0, 0}, /* 0x46 (01000110) */
    {1, 2, 3, 7, 0, 0, 0, 0}, /* 0x47 (01000111) */
    {4, 7, 0, 0, 0, 0, 0, 0}, /* 0x48 (01001000) */
    {1, 4, 7, 0, 0, 0, 0, 0}, /* 0x49 (01001001) */
    {2, 4, 7, 0, 0, 0, 0, 0}, /* 0x4A (01001010) */
    {1, 2, 4, 7, 0, 0, 0, 0}, /* 0x4B (01001011) */
    {3, 4, 7, 0, 0, 0, 0, 0}, /* 0x4C (01001100) */
    {1, 3, 4, 7, 0, 0, 0, 0}, /* 0x4D (01001101) */
    {2, 3, 4, 7, 0, 0, 0, 0}, /* 0x4E (01001110) */
    {1, 2, 3, 4, 7, 0, 0, 0}, /* 0x4F (01001111) */
    {5, 7, 0, 0, 0, 0, 0, 0}, /* 0x50 (01010000) */
    {1, 5, 7, 0, 0, 0, 0, 0}, /* 0x51 (01010001) */
    {2, 5, 7, 0, 0, 0, 0, 0}, /* 0x52 (01010010) */
    {1, 2, 5, 7, 0, 0, 0, 0}, /* 0x53 (01010011) */
    {3, 5, 7, 0, 0, 0, 0, 0}, /* 0x54 (01010100) */
    {1, 3, 5, 7, 0, 0, 0, 0}, /* 0x55 (01010101) */
    {2, 3, 5, 7, 0, 0, 0, 0}, /* 0x56 (01010110) */
    {1, 2, 3, 5, 7, 0, 0, 0}, /* 0x57 (01010111) */
    {4, 5, 7, 0, 0, 0, 0, 0}, /* 0x58 (01011000) */
    {1, 4, 5, 7, 0, 0, 0, 0}, /* 0x59 (01011001) */
    {2, 4, 5, 7, 0, 0, 0, 0}, /* 0x5A (01011010) */
    {1, 2, 4, 5, 7, 0, 0, 0}, /* 0x5B (01011011) */
    {3, 4, 5, 7, 0, 0, 0, 0}, /* 0x5C (01011100) */
    {1, 3, 4, 5, 7, 0, 0, 0}, /* 0x5D (01011101) */
    {2, 3, 4, 5, 7, 0, 0, 0}, /* 0x5E (01011110) */
    {1, 2, 3, 4, 5, 7, 0, 0}, /* 0x5F (01011111) */
    {6, 7, 0, 0, 0, 0, 0, 0}, /* 0x60 (01100000) */
    {1, 6, 7, 0, 0, 0, 0, 0}, /* 0x61 (01100001) */
    {2, 6, 7, 0, 0, 0, 0, 0}, /* 0x62 (01100010) */
    {1, 2, 6, 7, 0, 0, 0, 0}, /* 0x63 (01100011) */
    {3, 6, 7, 0, 0, 0, 0, 0}, /* 0x64 (01100100) */
    {1, 3, 6, 7, 0, 0, 0, 0}, /* 0x65 (01100101) */
    {2, 3, 6, 7, 0, 0, 0, 0}, /* 0x66 (01100110) */
    {1, 2, 3, 6, 7, 0, 0, 0}, /* 0x67 (01100111) */
    {4, 6, 7, 0, 0, 0, 0, 0}, /* 0x68 (01101000) */
    {1, 4, 6, 7, 0, 0, 0, 0}, /* 0x69 (01101001) */
    {2, 4, 6, 7, 0, 0, 0, 0}, /* 0x6A (01101010) */
    {1, 2, 4, 6, 7, 0, 0, 0}, /* 0x6B (01101011) */
    {3, 4, 6, 7, 0, 0, 0, 0}, /* 0x6C (01101100) */
    {1, 3, 4, 6, 7, 0, 0, 0}, /* 0x6D (01101101) */
    {2, 3, 4, 6, 7, 0, 0, 0}, /* 0x6E (01101110) */
    {1, 2, 3, 4, 6, 7, 0, 0}, /* 0x6F (01101111) */
    {5, 6, 7, 0, 0, 0, 0, 0}, /* 0x70 (01110000) */
    {1, 5, 6, 7, 0, 0, 0, 0}, /* 0x71 (01110001) */
    {2, 5, 6, 7, 0, 0, 0, 0}, /* 0x72 (01110010) */
    {1, 2, 5, 6, 7, 0, 0, 0}, /* 0x73 (01110011) */
    {3, 5, 6, 7, 0, 0, 0, 0}, /* 0x74 (01110100) */
    {1, 3, 5, 6, 7, 0, 0, 0}, /* 0x75 (01110101) */
    {2, 3, 5, 6, 7, 0, 0, 0}, /* 0x76 (01110110) */
    {1, 2, 3, 5, 6, 7, 0, 0}, /* 0x77 (01110111) */
    {4, 5, 6, 7, 0, 0, 0, 0}, /* 0x78 (01111000) */
    {1, 4, 5, 6, 7, 0, 0, 0}, /* 0x79 (01111001) */
    {2, 4, 5, 6, 7, 0, 0, 0}, /* 0x7A (01111010) */
    {1, 2, 4, 5, 6, 7, 0, 0}, /* 0x7B (01111011) */
    {3, 4, 5, 6, 7, 0, 0, 0}, /* 0x7C (01111100) */
    {1, 3, 4, 5, 6, 7, 0, 0}, /* 0x7D (01111101) */
    {2, 3, 4, 5, 6, 7, 0, 0}, /* 0x7E (01111110) */
    {1, 2, 3, 4, 5, 6, 7, 0}, /* 0x7F (01111111) */
    {8, 0, 0, 0, 0, 0, 0, 0}, /* 0x80 (10000000) */
    {1, 8, 0, 0, 0, 0, 0, 0}, /* 0x81 (10000001) */
    {2, 8, 0, 0, 0, 0, 0, 0}, /* 0x82 (10000010) */
    {1, 2, 8, 0, 0, 0, 0, 0}, /* 0x83 (10000011) */
    {3, 8, 0, 0, 0, 0, 0, 0}, /* 0x84 (10000100) */
    {1, 3, 8, 0, 0, 0, 0, 0}, /* 0x85 (10000101) */
    {2, 3, 8, 0, 0, 0, 0, 0}, /* 0x86 (10000110) */
    {1, 2, 3, 8, 0, 0, 0, 0}, /* 0x87 (10000111) */
    {4, 8, 0, 0, 0, 0, 0, 0}, /* 0x88 (10001000) */
    {1, 4, 8, 0, 0, 0, 0, 0}, /* 0x89 (10001001) */
    {2, 4, 8, 0, 0, 0, 0, 0}, /* 0x8A (10001010) */
    {1, 2, 4, 8, 0, 0, 0, 0}, /* 0x8B (10001011) */
    {3, 4, 8, 0, 0, 0, 0, 0}, /* 0x8C (10001100) */
    {1, 3, 4, 8, 0, 0, 0, 0}, /* 0x8D (10001101) */
    {2, 3, 4, 8, 0, 0, 0, 0}, /* 0x8E (10001110) */
    {1, 2, 3, 4, 8, 0, 0, 0}, /* 0x8F (10001111) */
    {5, 8, 0, 0, 0, 0, 0, 0}, /* 0x90 (10010000) */
    {1, 5, 8, 0, 0, 0, 0, 0}, /* 0x91 (10010001) */
    {2, 5, 8, 0, 0, 0, 0, 0}, /* 0x92 (10010010) */
    {1, 2, 5, 8, 0, 0, 0, 0}, /* 0x93 (10010011) */
    {3, 5, 8, 0, 0, 0, 0, 0}, /* 0x94 (10010100) */
    {1, 3, 5, 8, 0, 0, 0, 0}, /* 0x95 (10010101) */
    {2, 3, 5, 8, 0, 0, 0, 0}, /* 0x96 (10010110) */
    {1, 2, 3, 5, 8, 0, 0, 0}, /* 0x97 (10010111) */
    {4, 5, 8, 0, 0, 0, 0, 0}, /* 0x98 (10011000) */
    {1, 4, 5, 8, 0, 0, 0, 0}, /* 0x99 (10011001) */
    {2, 4, 5, 8, 0, 0, 0, 0}, /* 0x9A (10011010) */
    {1, 2, 4, 5, 8, 0, 0, 0}, /* 0x9B (10011011) */
    {3, 4, 5, 8, 0, 0, 0, 0}, /* 0x9C (10011100) */
    {1, 3, 4, 5, 8, 0, 0, 0}, /* 0x9D (10011101) */
    {2, 3, 4, 5, 8, 0, 0, 0}, /* 0x9E (10011110) */
    {1, 2, 3, 4, 5, 8, 0, 0}, /* 0x9F (10011111) */
    {6, 8, 0, 0, 0, 0, 0, 0}, /* 0xA0 (10100000) */
    {1, 6, 8, 0, 0, 0, 0, 0}, /* 0xA1 (10100001) */
    {2, 6, 8, 0, 0, 0, 0, 0}, /* 0xA2 (10100010) */
    {1, 2, 6, 8, 0, 0, 0, 0}, /* 0xA3 (10100011) */
    {3, 6, 8, 0, 0, 0, 0, 0}, /* 0xA4 (10100100) */
    {1, 3, 6, 8, 0, 0, 0, 0}, /* 0xA5 (10100101) */
    {2, 3, 6, 8, 0, 0, 0, 0}, /* 0xA6 (10100110) */
    {1, 2, 3, 6, 8, 0, 0, 0}, /* 0xA7 (10100111) */
    {4, 6, 8, 0, 0, 0, 0, 0}, /* 0xA8 (10101000) */
    {1, 4, 6, 8, 0, 0, 0, 0}, /* 0xA9 (10101001) */
    {2, 4, 6, 8, 0, 0, 0, 0}, /* 0xAA (10101010) */
    {1, 2, 4, 6, 8, 0, 0, 0}, /* 0xAB (10101011) */
    {3, 4, 6, 8, 0, 0, 0, 0}, /* 0xAC (10101100) */
    {1, 3, 4, 6, 8, 0, 0, 0}, /* 0xAD (10101101) */
    {2, 3, 4, 6, 8, 0, 0, 0}, /* 0xAE (10101110) */
    {1, 2, 3, 4, 6, 8, 0, 0}, /* 0xAF (10101111) */
    {5, 6, 8, 0, 0, 0, 0, 0}, /* 0xB0 (10110000) */
    {1, 5, 6, 8, 0, 0, 0, 0}, /* 0xB1 (10110001) */
    {2, 5, 6, 8, 0, 0, 0, 0}, /* 0xB2 (10110010) */
    {1, 2, 5, 6, 8, 0, 0, 0}, /* 0xB3 (10110011) */
    {3, 5, 6, 8, 0, 0, 0, 0}, /* 0xB4 (10110100) */
    {1, 3, 5, 6, 8, 0, 0, 0}, /* 0xB5 (10110101) */
    {2, 3, 5, 6, 8, 0, 0, 0}, /* 0xB6 (10110110) */
    {1, 2, 3, 5, 6, 8, 0, 0}, /* 0xB7 (10110111) */
    {4, 5, 6, 8, 0, 0, 0, 0}, /* 0xB8 (10111000) */
    {1, 4, 5, 6, 8, 0, 0, 0}, /* 0xB9 (10111001) */
    {2, 4, 5, 6, 8, 0, 0, 0}, /* 0xBA (10111010) */
    {1, 2, 4, 5, 6, 8, 0, 0}, /* 0xBB (10111011) */
    {3, 4, 5, 6, 8, 0, 0, 0}, /* 0xBC (10111100) */
    {1, 3, 4, 5, 6, 8, 0, 0}, /* 0xBD (10111101) */
    {2, 3, 4, 5, 6, 8, 0, 0}, /* 0xBE (10111110) */
    {1, 2, 3, 4, 5, 6, 8, 0}, /* 0xBF (10111111) */
    {7, 8, 0, 0, 0, 0, 0, 0}, /* 0xC0 (11000000) */
    {1, 7, 8, 0, 0, 0, 0, 0}, /* 0xC1 (11000001) */
    {2, 7, 8, 0, 0, 0, 0, 0}, /* 0xC2 (11000010) */
    {1, 2, 7, 8, 0, 0, 0, 0}, /* 0xC3 (11000011) */
    {3, 7, 8, 0, 0, 0, 0, 0}, /* 0xC4 (11000100) */
    {1, 3, 7, 8, 0, 0, 0, 0}, /* 0xC5 (11000101) */
    {2, 3, 7, 8, 0, 0, 0, 0}, /* 0xC6 (11000110) */
    {1, 2, 3, 7, 8, 0, 0, 0}, /* 0xC7 (11000111) */
    {4, 7, 8, 0, 0, 0, 0, 0}, /* 0xC8 (11001000) */
    {1, 4, 7, 8, 0, 0, 0, 0}, /* 0xC9 (11001001) */
    {2, 4, 7, 8, 0, 0, 0, 0}, /* 0xCA (11001010) */
    {1, 2, 4, 7, 8, 0, 0, 0}, /* 0xCB (11001011) */
    {3, 4, 7, 8, 0, 0, 0, 0}, /* 0xCC (11001100) */
    {1, 3, 4, 7, 8, 0, 0, 0}, /* 0xCD (11001101) */
    {2, 3, 4, 7, 8, 0, 0, 0}, /* 0xCE (11001110) */
    {1, 2, 3, 4, 7, 8, 0, 0}, /* 0xCF (11001111) */
    {5, 7, 8, 0, 0, 0, 0, 0}, /* 0xD0 (11010000) */
    {1, 5, 7, 8, 0, 0, 0, 0}, /* 0xD1 (11010001) */
    {2, 5, 7, 8, 0, 0, 0, 0}, /* 0xD2 (11010010) */
    {1, 2, 5, 7, 8, 0, 0, 0}, /* 0xD3 (11010011) */
    {3, 5, 7, 8, 0, 0, 0, 0}, /* 0xD4 (11010100) */
    {1, 3, 5, 7, 8, 0, 0, 0}, /* 0xD5 (11010101) */
    {2, 3, 5, 7, 8, 0, 0, 0}, /* 0xD6 (11010110) */
    {1, 2, 3, 5, 7, 8, 0, 0}, /* 0xD7 (11010111) */
    {4, 5, 7, 8, 0, 0, 0, 0}, /* 0xD8 (11011000) */
    {1, 4, 5, 7, 8, 0, 0, 0}, /* 0xD9 (11011001) */
    {2, 4, 5, 7, 8, 0, 0, 0}, /* 0xDA (11011010) */
    {1, 2, 4, 5, 7, 8, 0, 0}, /* 0xDB (11011011) */
    {3, 4, 5, 7, 8, 0, 0, 0}, /* 0xDC (11011100) */
    {1, 3, 4, 5, 7, 8, 0, 0}, /* 0xDD (11011101) */
    {2, 3, 4, 5, 7, 8, 0, 0}, /* 0xDE (11011110) */
    {1, 2, 3, 4, 5, 7, 8, 0}, /* 0xDF (11011111) */
    {6, 7, 8, 0, 0, 0, 0, 0}, /* 0xE0 (11100000) */
    {1, 6, 7, 8, 0, 0, 0, 0}, /* 0xE1 (11100001) */
    {2, 6, 7, 8, 0, 0, 0, 0}, /* 0xE2 (11100010) */
    {1, 2, 6, 7, 8, 0, 0, 0}, /* 0xE3 (11100011) */
    {3, 6, 7, 8, 0, 0, 0, 0}, /* 0xE4 (11100100) */
    {1, 3, 6, 7, 8, 0, 0, 0}, /* 0xE5 (11100101) */
    {2, 3, 6, 7, 8, 0, 0, 0}, /* 0xE6 (11100110) */
    {1, 2, 3, 6, 7, 8, 0, 0}, /* 0xE7 (11100111) */
    {4, 6, 7, 8, 0, 0, 0, 0}, /* 0xE8 (11101000) */
    {1, 4, 6, 7, 8, 0, 0, 0}, /* 0xE9 (11101001) */
    {2, 4, 6, 7, 8, 0, 0, 0}, /* 0xEA (11101010) */
    {1, 2, 4, 6, 7, 8, 0, 0}, /* 0xEB (11101011) */
    {3, 4, 6, 7, 8, 0, 0, 0}, /* 0xEC (11101100) */
    {1, 3, 4, 6, 7, 8, 0, 0}, /* 0xED (11101101) */
    {2, 3, 4, 6, 7, 8, 0, 0}, /* 0xEE (11101110) */
    {1, 2, 3, 4, 6, 7, 8, 0}, /* 0xEF (11101111) */
    {5, 6, 7, 8, 0, 0, 0, 0}, /* 0xF0 (11110000) */
    {1, 5, 6, 7, 8, 0, 0, 0}, /* 0xF1 (11110001) */
    {2, 5, 6, 7, 8, 0, 0, 0}, /* 0xF2 (11110010) */
    {1, 2, 5, 6, 7, 8, 0, 0}, /* 0xF3 (11110011) */
    {3, 5, 6, 7, 8, 0, 0, 0}, /* 0xF4 (11110100) */
    {1, 3, 5, 6, 7, 8, 0, 0}, /* 0xF5 (11110101) */
    {2, 3, 5, 6, 7, 8, 0, 0}, /* 0xF6 (11110110) */
    {1, 2, 3, 5, 6, 7, 8, 0}, /* 0xF7 (11110111) */
    {4, 5, 6, 7, 8, 0, 0, 0}, /* 0xF8 (11111000) */
    {1, 4, 5, 6, 7, 8, 0, 0}, /* 0xF9 (11111001) */
    {2, 4, 5, 6, 7, 8, 0, 0}, /* 0xFA (11111010) */
    {1, 2, 4, 5, 6, 7, 8, 0}, /* 0xFB (11111011) */
    {3, 4, 5, 6, 7, 8, 0, 0}, /* 0xFC (11111100) */
    {1, 3, 4, 5, 6, 7, 8, 0}, /* 0xFD (11111101) */
    {2, 3, 4, 5, 6, 7, 8, 0}, /* 0xFE (11111110) */
    {1, 2, 3, 4, 5, 6, 7, 8}  /* 0xFF (11111111) */
};

#endif  // #ifdef CROARING_IS_X64

#ifdef CROARING_IS_X64
// same as vecDecodeTable but in 16 bits
ALIGNED(32)
static uint16_t vecDecodeTable_uint16[256][8] = {
    {0, 0, 0, 0, 0, 0, 0, 0}, /* 0x00 (00000000) */
    {1, 0, 0, 0, 0, 0, 0, 0}, /* 0x01 (00000001) */
    {2, 0, 0, 0, 0, 0, 0, 0}, /* 0x02 (00000010) */
    {1, 2, 0, 0, 0, 0, 0, 0}, /* 0x03 (00000011) */
    {3, 0, 0, 0, 0, 0, 0, 0}, /* 0x04 (00000100) */
    {1, 3, 0, 0, 0, 0, 0, 0}, /* 0x05 (00000101) */
    {2, 3, 0, 0, 0, 0, 0, 0}, /* 0x06 (00000110) */
    {1, 2, 3, 0, 0, 0, 0, 0}, /* 0x07 (00000111) */
    {4, 0, 0, 0, 0, 0, 0, 0}, /* 0x08 (00001000) */
    {1, 4, 0, 0, 0, 0, 0, 0}, /* 0x09 (00001001) */
    {2, 4, 0, 0, 0, 0, 0, 0}, /* 0x0A (00001010) */
    {1, 2, 4, 0, 0, 0, 0, 0}, /* 0x0B (00001011) */
    {3, 4, 0, 0, 0, 0, 0, 0}, /* 0x0C (00001100) */
    {1, 3, 4, 0, 0, 0, 0, 0}, /* 0x0D (00001101) */
    {2, 3, 4, 0, 0, 0, 0, 0}, /* 0x0E (00001110) */
    {1, 2, 3, 4, 0, 0, 0, 0}, /* 0x0F (00001111) */
    {5, 0, 0, 0, 0, 0, 0, 0}, /* 0x10 (00010000) */
    {1, 5, 0, 0, 0, 0, 0, 0}, /* 0x11 (00010001) */
    {2, 5, 0, 0, 0, 0, 0, 0}, /* 0x12 (00010010) */
    {1, 2, 5, 0, 0, 0, 0, 0}, /* 0x13 (00010011) */
    {3, 5, 0, 0, 0, 0, 0, 0}, /* 0x14 (00010100) */
    {1, 3, 5, 0, 0, 0, 0, 0}, /* 0x15 (00010101) */
    {2, 3, 5, 0, 0, 0, 0, 0}, /* 0x16 (00010110) */
    {1, 2, 3, 5, 0, 0, 0, 0}, /* 0x17 (00010111) */
    {4, 5, 0, 0, 0, 0, 0, 0}, /* 0x18 (00011000) */
    {1, 4, 5, 0, 0, 0, 0, 0}, /* 0x19 (00011001) */
    {2, 4, 5, 0, 0, 0, 0, 0}, /* 0x1A (00011010) */
    {1, 2, 4, 5, 0, 0, 0, 0}, /* 0x1B (00011011) */
    {3, 4, 5, 0, 0, 0, 0, 0}, /* 0x1C (00011100) */
    {1, 3, 4, 5, 0, 0, 0, 0}, /* 0x1D (00011101) */
    {2, 3, 4, 5, 0, 0, 0, 0}, /* 0x1E (00011110) */
    {1, 2, 3, 4, 5, 0, 0, 0}, /* 0x1F (00011111) */
    {6, 0, 0, 0, 0, 0, 0, 0}, /* 0x20 (00100000) */
    {1, 6, 0, 0, 0, 0, 0, 0}, /* 0x21 (00100001) */
    {2, 6, 0, 0, 0, 0, 0, 0}, /* 0x22 (00100010) */
    {1, 2, 6, 0, 0, 0, 0, 0}, /* 0x23 (00100011) */
    {3, 6, 0, 0, 0, 0, 0, 0}, /* 0x24 (00100100) */
    {1, 3, 6, 0, 0, 0, 0, 0}, /* 0x25 (00100101) */
    {2, 3, 6, 0, 0, 0, 0, 0}, /* 0x26 (00100110) */
    {1, 2, 3, 6, 0, 0, 0, 0}, /* 0x27 (00100111) */
    {4, 6, 0, 0, 0, 0, 0, 0}, /* 0x28 (00101000) */
    {1, 4, 6, 0, 0, 0, 0, 0}, /* 0x29 (00101001) */
    {2, 4, 6, 0, 0, 0, 0, 0}, /* 0x2A (00101010) */
    {1, 2, 4, 6, 0, 0, 0, 0}, /* 0x2B (00101011) */
    {3, 4, 6, 0, 0, 0, 0, 0}, /* 0x2C (00101100) */
    {1, 3, 4, 6, 0, 0, 0, 0}, /* 0x2D (00101101) */
    {2, 3, 4, 6, 0, 0, 0, 0}, /* 0x2E (00101110) */
    {1, 2, 3, 4, 6, 0, 0, 0}, /* 0x2F (00101111) */
    {5, 6, 0, 0, 0, 0, 0, 0}, /* 0x30 (00110000) */
    {1, 5, 6, 0, 0, 0, 0, 0}, /* 0x31 (00110001) */
    {2, 5, 6, 0, 0, 0, 0, 0}, /* 0x32 (00110010) */
    {1, 2, 5, 6, 0, 0, 0, 0}, /* 0x33 (00110011) */
    {3, 5, 6, 0, 0, 0, 0, 0}, /* 0x34 (00110100) */
    {1, 3, 5, 6, 0, 0, 0, 0}, /* 0x35 (00110101) */
    {2, 3, 5, 6, 0, 0, 0, 0}, /* 0x36 (00110110) */
    {1, 2, 3, 5, 6, 0, 0, 0}, /* 0x37 (00110111) */
    {4, 5, 6, 0, 0, 0, 0, 0}, /* 0x38 (00111000) */
    {1, 4, 5, 6, 0, 0, 0, 0}, /* 0x39 (00111001) */
    {2, 4, 5, 6, 0, 0, 0, 0}, /* 0x3A (00111010) */
    {1, 2, 4, 5, 6, 0, 0, 0}, /* 0x3B (00111011) */
    {3, 4, 5, 6, 0, 0, 0, 0}, /* 0x3C (00111100) */
    {1, 3, 4, 5, 6, 0, 0, 0}, /* 0x3D (00111101) */
    {2, 3, 4, 5, 6, 0, 0, 0}, /* 0x3E (00111110) */
    {1, 2, 3, 4, 5, 6, 0, 0}, /* 0x3F (00111111) */
    {7, 0, 0, 0, 0, 0, 0, 0}, /* 0x40 (01000000) */
    {1, 7, 0, 0, 0, 0, 0, 0}, /* 0x41 (01000001) */
    {2, 7, 0, 0, 0, 0, 0, 0}, /* 0x42 (01000010) */
    {1, 2, 7, 0, 0, 0, 0, 0}, /* 0x43 (01000011) */
    {3, 7, 0, 0, 0, 0, 0, 0}, /* 0x44 (01000100) */
    {1, 3, 7, 0, 0, 0, 0, 0}, /* 0x45 (01000101) */
    {2, 3, 7, 0, 0, 0, 0, 0}, /* 0x46 (01000110) */
    {1, 2, 3, 7, 0, 0, 0, 0}, /* 0x47 (01000111) */
    {4, 7, 0, 0, 0, 0, 0, 0}, /* 0x48 (01001000) */
    {1, 4, 7, 0, 0, 0, 0, 0}, /* 0x49 (01001001) */
    {2, 4, 7, 0, 0, 0, 0, 0}, /* 0x4A (01001010) */
    {1, 2, 4, 7, 0, 0, 0, 0}, /* 0x4B (01001011) */
    {3, 4, 7, 0, 0, 0, 0, 0}, /* 0x4C (01001100) */
    {1, 3, 4, 7, 0, 0, 0, 0}, /* 0x4D (01001101) */
    {2, 3, 4, 7, 0, 0, 0, 0}, /* 0x4E (01001110) */
    {1, 2, 3, 4, 7, 0, 0, 0}, /* 0x4F (01001111) */
    {5, 7, 0, 0, 0, 0, 0, 0}, /* 0x50 (01010000) */
    {1, 5, 7, 0, 0, 0, 0, 0}, /* 0x51 (01010001) */
    {2, 5, 7, 0, 0, 0, 0, 0}, /* 0x52 (01010010) */
    {1, 2, 5, 7, 0, 0, 0, 0}, /* 0x53 (01010011) */
    {3, 5, 7, 0, 0, 0, 0, 0}, /* 0x54 (01010100) */
    {1, 3, 5, 7, 0, 0, 0, 0}, /* 0x55 (01010101) */
    {2, 3, 5, 7, 0, 0, 0, 0}, /* 0x56 (01010110) */
    {1, 2, 3, 5, 7, 0, 0, 0}, /* 0x57 (01010111) */
    {4, 5, 7, 0, 0, 0, 0, 0}, /* 0x58 (01011000) */
    {1, 4, 5, 7, 0, 0, 0, 0}, /* 0x59 (01011001) */
    {2, 4, 5, 7, 0, 0, 0, 0}, /* 0x5A (01011010) */
    {1, 2, 4, 5, 7, 0, 0, 0}, /* 0x5B (01011011) */
    {3, 4, 5, 7, 0, 0, 0, 0}, /* 0x5C (01011100) */
    {1, 3, 4, 5, 7, 0, 0, 0}, /* 0x5D (01011101) */
    {2, 3, 4, 5, 7, 0, 0, 0}, /* 0x5E (01011110) */
    {1, 2, 3, 4, 5, 7, 0, 0}, /* 0x5F (01011111) */
    {6, 7, 0, 0, 0, 0, 0, 0}, /* 0x60 (01100000) */
    {1, 6, 7, 0, 0, 0, 0, 0}, /* 0x61 (01100001) */
    {2, 6, 7, 0, 0, 0, 0, 0}, /* 0x62 (01100010) */
    {1, 2, 6, 7, 0, 0, 0, 0}, /* 0x63 (01100011) */
    {3, 6, 7, 0, 0, 0, 0, 0}, /* 0x64 (01100100) */
    {1, 3, 6, 7, 0, 0, 0, 0}, /* 0x65 (01100101) */
    {2, 3, 6, 7, 0, 0, 0, 0}, /* 0x66 (01100110) */
    {1, 2, 3, 6, 7, 0, 0, 0}, /* 0x67 (01100111) */
    {4, 6, 7, 0, 0, 0, 0, 0}, /* 0x68 (01101000) */
    {1, 4, 6, 7, 0, 0, 0, 0}, /* 0x69 (01101001) */
    {2, 4, 6, 7, 0, 0, 0, 0}, /* 0x6A (01101010) */
    {1, 2, 4, 6, 7, 0, 0, 0}, /* 0x6B (01101011) */
    {3, 4, 6, 7, 0, 0, 0, 0}, /* 0x6C (01101100) */
    {1, 3, 4, 6, 7, 0, 0, 0}, /* 0x6D (01101101) */
    {2, 3, 4, 6, 7, 0, 0, 0}, /* 0x6E (01101110) */
    {1, 2, 3, 4, 6, 7, 0, 0}, /* 0x6F (01101111) */
    {5, 6, 7, 0, 0, 0, 0, 0}, /* 0x70 (01110000) */
    {1, 5, 6, 7, 0, 0, 0, 0}, /* 0x71 (01110001) */
    {2, 5, 6, 7, 0, 0, 0, 0}, /* 0x72 (01110010) */
    {1, 2, 5, 6, 7, 0, 0, 0}, /* 0x73 (01110011) */
    {3, 5, 6, 7, 0, 0, 0, 0}, /* 0x74 (01110100) */
    {1, 3, 5, 6, 7, 0, 0, 0}, /* 0x75 (01110101) */
    {2, 3, 5, 6, 7, 0, 0, 0}, /* 0x76 (01110110) */
    {1, 2, 3, 5, 6, 7, 0, 0}, /* 0x77 (01110111) */
    {4, 5, 6, 7, 0, 0, 0, 0}, /* 0x78 (01111000) */
    {1, 4, 5, 6, 7, 0, 0, 0}, /* 0x79 (01111001) */
    {2, 4, 5, 6, 7, 0, 0, 0}, /* 0x7A (01111010) */
    {1, 2, 4, 5, 6, 7, 0, 0}, /* 0x7B (01111011) */
    {3, 4, 5, 6, 7, 0, 0, 0}, /* 0x7C (01111100) */
    {1, 3, 4, 5, 6, 7, 0, 0}, /* 0x7D (01111101) */
    {2, 3, 4, 5, 6, 7, 0, 0}, /* 0x7E (01111110) */
    {1, 2, 3, 4, 5, 6, 7, 0}, /* 0x7F (01111111) */
    {8, 0, 0, 0, 0, 0, 0, 0}, /* 0x80 (10000000) */
    {1, 8, 0, 0, 0, 0, 0, 0}, /* 0x81 (10000001) */
    {2, 8, 0, 0, 0, 0, 0, 0}, /* 0x82 (10000010) */
    {1, 2, 8, 0, 0, 0, 0, 0}, /* 0x83 (10000011) */
    {3, 8, 0, 0, 0, 0, 0, 0}, /* 0x84 (10000100) */
    {1, 3, 8, 0, 0, 0, 0, 0}, /* 0x85 (10000101) */
    {2, 3, 8, 0, 0, 0, 0, 0}, /* 0x86 (10000110) */
    {1, 2, 3, 8, 0, 0, 0, 0}, /* 0x87 (10000111) */
    {4, 8, 0, 0, 0, 0, 0, 0}, /* 0x88 (10001000) */
    {1, 4, 8, 0, 0, 0, 0, 0}, /* 0x89 (10001001) */
    {2, 4, 8, 0, 0, 0, 0, 0}, /* 0x8A (10001010) */
    {1, 2, 4, 8, 0, 0, 0, 0}, /* 0x8B (10001011) */
    {3, 4, 8, 0, 0, 0, 0, 0}, /* 0x8C (10001100) */
    {1, 3, 4, 8, 0, 0, 0, 0}, /* 0x8D (10001101) */
    {2, 3, 4, 8, 0, 0, 0, 0}, /* 0x8E (10001110) */
    {1, 2, 3, 4, 8, 0, 0, 0}, /* 0x8F (10001111) */
    {5, 8, 0, 0, 0, 0, 0, 0}, /* 0x90 (10010000) */
    {1, 5, 8, 0, 0, 0, 0, 0}, /* 0x91 (10010001) */
    {2, 5, 8, 0, 0, 0, 0, 0}, /* 0x92 (10010010) */
    {1, 2, 5, 8, 0, 0, 0, 0}, /* 0x93 (10010011) */
    {3, 5, 8, 0, 0, 0, 0, 0}, /* 0x94 (10010100) */
    {1, 3, 5, 8, 0, 0, 0, 0}, /* 0x95 (10010101) */
    {2, 3, 5, 8, 0, 0, 0, 0}, /* 0x96 (10010110) */
    {1, 2, 3, 5, 8, 0, 0, 0}, /* 0x97 (10010111) */
    {4, 5, 8, 0, 0, 0, 0, 0}, /* 0x98 (10011000) */
    {1, 4, 5, 8, 0, 0, 0, 0}, /* 0x99 (10011001) */
    {2, 4, 5, 8, 0, 0, 0, 0}, /* 0x9A (10011010) */
    {1, 2, 4, 5, 8, 0, 0, 0}, /* 0x9B (10011011) */
    {3, 4, 5, 8, 0, 0, 0, 0}, /* 0x9C (10011100) */
    {1, 3, 4, 5, 8, 0, 0, 0}, /* 0x9D (10011101) */
    {2, 3, 4, 5, 8, 0, 0, 0}, /* 0x9E (10011110) */
    {1, 2, 3, 4, 5, 8, 0, 0}, /* 0x9F (10011111) */
    {6, 8, 0, 0, 0, 0, 0, 0}, /* 0xA0 (10100000) */
    {1, 6, 8, 0, 0, 0, 0, 0}, /* 0xA1 (10100001) */
    {2, 6, 8, 0, 0, 0, 0, 0}, /* 0xA2 (10100010) */
    {1, 2, 6, 8, 0, 0, 0, 0}, /* 0xA3 (10100011) */
    {3, 6, 8, 0, 0, 0, 0, 0}, /* 0xA4 (10100100) */
    {1, 3, 6, 8, 0, 0, 0, 0}, /* 0xA5 (10100101) */
    {2, 3, 6, 8, 0, 0, 0, 0}, /* 0xA6 (10100110) */
    {1, 2, 3, 6, 8, 0, 0, 0}, /* 0xA7 (10100111) */
    {4, 6, 8, 0, 0, 0, 0, 0}, /* 0xA8 (10101000) */
    {1, 4, 6, 8, 0, 0, 0, 0}, /* 0xA9 (10101001) */
    {2, 4, 6, 8, 0, 0, 0, 0}, /* 0xAA (10101010) */
    {1, 2, 4, 6, 8, 0, 0, 0}, /* 0xAB (10101011) */
    {3, 4, 6, 8, 0, 0, 0, 0}, /* 0xAC (10101100) */
    {1, 3, 4, 6, 8, 0, 0, 0}, /* 0xAD (10101101) */
    {2, 3, 4, 6, 8, 0, 0, 0}, /* 0xAE (10101110) */
    {1, 2, 3, 4, 6, 8, 0, 0}, /* 0xAF (10101111) */
    {5, 6, 8, 0, 0, 0, 0, 0}, /* 0xB0 (10110000) */
    {1, 5, 6, 8, 0, 0, 0, 0}, /* 0xB1 (10110001) */
    {2, 5, 6, 8, 0, 0, 0, 0}, /* 0xB2 (10110010) */
    {1, 2, 5, 6, 8, 0, 0, 0}, /* 0xB3 (10110011) */
    {3, 5, 6, 8, 0, 0, 0, 0}, /* 0xB4 (10110100) */
    {1, 3, 5, 6, 8, 0, 0, 0}, /* 0xB5 (10110101) */
    {2, 3, 5, 6, 8, 0, 0, 0}, /* 0xB6 (10110110) */
    {1, 2, 3, 5, 6, 8, 0, 0}, /* 0xB7 (10110111) */
    {4, 5, 6, 8, 0, 0, 0, 0}, /* 0xB8 (10111000) */
    {1, 4, 5, 6, 8, 0, 0, 0}, /* 0xB9 (10111001) */
    {2, 4, 5, 6, 8, 0, 0, 0}, /* 0xBA (10111010) */
    {1, 2, 4, 5, 6, 8, 0, 0}, /* 0xBB (10111011) */
    {3, 4, 5, 6, 8, 0, 0, 0}, /* 0xBC (10111100) */
    {1, 3, 4, 5, 6, 8, 0, 0}, /* 0xBD (10111101) */
    {2, 3, 4, 5, 6, 8, 0, 0}, /* 0xBE (10111110) */
    {1, 2, 3, 4, 5, 6, 8, 0}, /* 0xBF (10111111) */
    {7, 8, 0, 0, 0, 0, 0, 0}, /* 0xC0 (11000000) */
    {1, 7, 8, 0, 0, 0, 0, 0}, /* 0xC1 (11000001) */
    {2, 7, 8, 0, 0, 0, 0, 0}, /* 0xC2 (11000010) */
    {1, 2, 7, 8, 0, 0, 0, 0}, /* 0xC3 (11000011) */
    {3, 7, 8, 0, 0, 0, 0, 0}, /* 0xC4 (11000100) */
    {1, 3, 7, 8, 0, 0, 0, 0}, /* 0xC5 (11000101) */
    {2, 3, 7, 8, 0, 0, 0, 0}, /* 0xC6 (11000110) */
    {1, 2, 3, 7, 8, 0, 0, 0}, /* 0xC7 (11000111) */
    {4, 7, 8, 0, 0, 0, 0, 0}, /* 0xC8 (11001000) */
    {1, 4, 7, 8, 0, 0, 0, 0}, /* 0xC9 (11001001) */
    {2, 4, 7, 8, 0, 0, 0, 0}, /* 0xCA (11001010) */
    {1, 2, 4, 7, 8, 0, 0, 0}, /* 0xCB (11001011) */
    {3, 4, 7, 8, 0, 0, 0, 0}, /* 0xCC (11001100) */
    {1, 3, 4, 7, 8, 0, 0, 0}, /* 0xCD (11001101) */
    {2, 3, 4, 7, 8, 0, 0, 0}, /* 0xCE (11001110) */
    {1, 2, 3, 4, 7, 8, 0, 0}, /* 0xCF (11001111) */
    {5, 7, 8, 0, 0, 0, 0, 0}, /* 0xD0 (11010000) */
    {1, 5, 7, 8, 0, 0, 0, 0}, /* 0xD1 (11010001) */
    {2, 5, 7, 8, 0, 0, 0, 0}, /* 0xD2 (11010010) */
    {1, 2, 5, 7, 8, 0, 0, 0}, /* 0xD3 (11010011) */
    {3, 5, 7, 8, 0, 0, 0, 0}, /* 0xD4 (11010100) */
    {1, 3, 5, 7, 8, 0, 0, 0}, /* 0xD5 (11010101) */
    {2, 3, 5, 7, 8, 0, 0, 0}, /* 0xD6 (11010110) */
    {1, 2, 3, 5, 7, 8, 0, 0}, /* 0xD7 (11010111) */
    {4, 5, 7, 8, 0, 0, 0, 0}, /* 0xD8 (11011000) */
    {1, 4, 5, 7, 8, 0, 0, 0}, /* 0xD9 (11011001) */
    {2, 4, 5, 7, 8, 0, 0, 0}, /* 0xDA (11011010) */
    {1, 2, 4, 5, 7, 8, 0, 0}, /* 0xDB (11011011) */
    {3, 4, 5, 7, 8, 0, 0, 0}, /* 0xDC (11011100) */
    {1, 3, 4, 5, 7, 8, 0, 0}, /* 0xDD (11011101) */
    {2, 3, 4, 5, 7, 8, 0, 0}, /* 0xDE (11011110) */
    {1, 2, 3, 4, 5, 7, 8, 0}, /* 0xDF (11011111) */
    {6, 7, 8, 0, 0, 0, 0, 0}, /* 0xE0 (11100000) */
    {1, 6, 7, 8, 0, 0, 0, 0}, /* 0xE1 (11100001) */
    {2, 6, 7, 8, 0, 0, 0, 0}, /* 0xE2 (11100010) */
    {1, 2, 6, 7, 8, 0, 0, 0}, /* 0xE3 (11100011) */
    {3, 6, 7, 8, 0, 0, 0, 0}, /* 0xE4 (11100100) */
    {1, 3, 6, 7, 8, 0, 0, 0}, /* 0xE5 (11100101) */
    {2, 3, 6, 7, 8, 0, 0, 0}, /* 0xE6 (11100110) */
    {1, 2, 3, 6, 7, 8, 0, 0}, /* 0xE7 (11100111) */
    {4, 6, 7, 8, 0, 0, 0, 0}, /* 0xE8 (11101000) */
    {1, 4, 6, 7, 8, 0, 0, 0}, /* 0xE9 (11101001) */
    {2, 4, 6, 7, 8, 0, 0, 0}, /* 0xEA (11101010) */
    {1, 2, 4, 6, 7, 8, 0, 0}, /* 0xEB (11101011) */
    {3, 4, 6, 7, 8, 0, 0, 0}, /* 0xEC (11101100) */
    {1, 3, 4, 6, 7, 8, 0, 0}, /* 0xED (11101101) */
    {2, 3, 4, 6, 7, 8, 0, 0}, /* 0xEE (11101110) */
    {1, 2, 3, 4, 6, 7, 8, 0}, /* 0xEF (11101111) */
    {5, 6, 7, 8, 0, 0, 0, 0}, /* 0xF0 (11110000) */
    {1, 5, 6, 7, 8, 0, 0, 0}, /* 0xF1 (11110001) */
    {2, 5, 6, 7, 8, 0, 0, 0}, /* 0xF2 (11110010) */
    {1, 2, 5, 6, 7, 8, 0, 0}, /* 0xF3 (11110011) */
    {3, 5, 6, 7, 8, 0, 0, 0}, /* 0xF4 (11110100) */
    {1, 3, 5, 6, 7, 8, 0, 0}, /* 0xF5 (11110101) */
    {2, 3, 5, 6, 7, 8, 0, 0}, /* 0xF6 (11110110) */
    {1, 2, 3, 5, 6, 7, 8, 0}, /* 0xF7 (11110111) */
    {4, 5, 6, 7, 8, 0, 0, 0}, /* 0xF8 (11111000) */
    {1, 4, 5, 6, 7, 8, 0, 0}, /* 0xF9 (11111001) */
    {2, 4, 5, 6, 7, 8, 0, 0}, /* 0xFA (11111010) */
    {1, 2, 4, 5, 6, 7, 8, 0}, /* 0xFB (11111011) */
    {3, 4, 5, 6, 7, 8, 0, 0}, /* 0xFC (11111100) */
    {1, 3, 4, 5, 6, 7, 8, 0}, /* 0xFD (11111101) */
    {2, 3, 4, 5, 6, 7, 8, 0}, /* 0xFE (11111110) */
    {1, 2, 3, 4, 5, 6, 7, 8}  /* 0xFF (11111111) */
};

#endif

#ifdef CROARING_IS_X64
CROARING_TARGET_AVX2
size_t bitset_extract_setbits_avx2(const uint64_t *words, size_t length,
                                   uint32_t *out, size_t outcapacity,
                                   uint32_t base) {
    uint32_t *initout = out;
    __m256i baseVec = _mm256_set1_epi32(base - 1);
    __m256i incVec = _mm256_set1_epi32(64);
    __m256i add8 = _mm256_set1_epi32(8);
    uint32_t *safeout = out + outcapacity;
    size_t i = 0;
    for (; (i < length) && (out + 64 <= safeout); ++i) {
        uint64_t w = words[i];
        if (w == 0) {
            baseVec = _mm256_add_epi32(baseVec, incVec);
        } else {
            for (int k = 0; k < 4; ++k) {
                uint8_t byteA = (uint8_t)w;
                uint8_t byteB = (uint8_t)(w >> 8);
                w >>= 16;
                __m256i vecA =
                    _mm256_load_si256((const __m256i *)vecDecodeTable[byteA]);
                __m256i vecB =
                    _mm256_load_si256((const __m256i *)vecDecodeTable[byteB]);
                uint8_t advanceA = lengthTable[byteA];
                uint8_t advanceB = lengthTable[byteB];
                vecA = _mm256_add_epi32(baseVec, vecA);
                baseVec = _mm256_add_epi32(baseVec, add8);
                vecB = _mm256_add_epi32(baseVec, vecB);
                baseVec = _mm256_add_epi32(baseVec, add8);
                _mm256_storeu_si256((__m256i *)out, vecA);
                out += advanceA;
                _mm256_storeu_si256((__m256i *)out, vecB);
                out += advanceB;
            }
        }
    }
    base += i * 64;
    for (; (i < length) && (out < safeout); ++i) {
        uint64_t w = words[i];
        while ((w != 0) && (out < safeout)) {
            uint64_t t = w & (~w + 1); // on x64, should compile to BLSI (careful: the Intel compiler seems to fail)
            int r = __builtin_ctzll(w); // on x64, should compile to TZCNT
            uint32_t val = r + base;
            memcpy(out, &val,
                   sizeof(uint32_t));  // should be compiled as a MOV on x64
            out++;
            w ^= t;
        }
        base += 64;
    }
    return out - initout;
}
CROARING_UNTARGET_REGION
#endif  // CROARING_IS_X64

size_t bitset_extract_setbits(const uint64_t *words, size_t length,
                              uint32_t *out, uint32_t base) {
    int outpos = 0;
    size_t i; for (i = 0; i < length; ++i) {
        uint64_t w = words[i];
        while (w != 0) {
            uint64_t t = w & (~w + 1); // on x64, should compile to BLSI (careful: the Intel compiler seems to fail)
            int r = __builtin_ctzll(w); // on x64, should compile to TZCNT
            uint32_t val = r + base;
            memcpy(out + outpos, &val,
                   sizeof(uint32_t));  // should be compiled as a MOV on x64
            outpos++;
            w ^= t;
        }
        base += 64;
    }
    return outpos;
}

size_t bitset_extract_intersection_setbits_uint16(const uint64_t * __restrict__ words1,
                                                  const uint64_t * __restrict__ words2,
                                                  size_t length, uint16_t *out,
                                                  uint16_t base) {
    int outpos = 0;
    size_t i; for (i = 0; i < length; ++i) {
        uint64_t w = words1[i] & words2[i];
        while (w != 0) {
            uint64_t t = w & (~w + 1);
            int r = __builtin_ctzll(w);
            out[outpos++] = r + base;
            w ^= t;
        }
        base += 64;
    }
    return outpos;
}

#ifdef CROARING_IS_X64
/*
 * Given a bitset containing "length" 64-bit words, write out the position
 * of all the set bits to "out" as 16-bit integers, values start at "base" (can
 *be set to zero).
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 *set.
 *
 * Returns how many values were actually decoded.
 *
 * This function uses SSE decoding.
 */
CROARING_TARGET_AVX2
static size_t bitset_extract_setbits_sse_uint16(const uint64_t *words, size_t length,
                                         uint16_t *out, size_t outcapacity,
                                         uint16_t base) {
    uint16_t *initout = out;
    __m128i baseVec = _mm_set1_epi16(base - 1);
    __m128i incVec = _mm_set1_epi16(64);
    __m128i add8 = _mm_set1_epi16(8);
    uint16_t *safeout = out + outcapacity;
    const int numberofbytes = 2;  // process two bytes at a time
    size_t i = 0;
    for (; (i < length) && (out + numberofbytes * 8 <= safeout); ++i) {
        uint64_t w = words[i];
        if (w == 0) {
            baseVec = _mm_add_epi16(baseVec, incVec);
        } else {
            for (int k = 0; k < 4; ++k) {
                uint8_t byteA = (uint8_t)w;
                uint8_t byteB = (uint8_t)(w >> 8);
                w >>= 16;
                __m128i vecA = _mm_load_si128(
                    (const __m128i *)vecDecodeTable_uint16[byteA]);
                __m128i vecB = _mm_load_si128(
                    (const __m128i *)vecDecodeTable_uint16[byteB]);
                uint8_t advanceA = lengthTable[byteA];
                uint8_t advanceB = lengthTable[byteB];
                vecA = _mm_add_epi16(baseVec, vecA);
                baseVec = _mm_add_epi16(baseVec, add8);
                vecB = _mm_add_epi16(baseVec, vecB);
                baseVec = _mm_add_epi16(baseVec, add8);
                _mm_storeu_si128((__m128i *)out, vecA);
                out += advanceA;
                _mm_storeu_si128((__m128i *)out, vecB);
                out += advanceB;
            }
        }
    }
    base += (uint16_t)(i * 64);
    for (; (i < length) && (out < safeout); ++i) {
        uint64_t w = words[i];
        while ((w != 0) && (out < safeout)) {
            uint64_t t = w & (~w + 1);
            int r = __builtin_ctzll(w);
            *out = r + base;
            out++;
            w ^= t;
        }
        base += 64;
    }
    return out - initout;
}
CROARING_UNTARGET_REGION
#endif

/*
 * Given a bitset containing "length" 64-bit words, write out the position
 * of all the set bits to "out", values start at "base" (can be set to zero).
 *
 * The "out" pointer should be sufficient to store the actual number of bits
 *set.
 *
 * Returns how many values were actually decoded.
 */
static size_t bitset_extract_setbits_uint16(const uint64_t *words, size_t length,
                                     uint16_t *out, uint16_t base) {
    int outpos = 0;
    size_t i; for (i = 0; i < length; ++i) {
        uint64_t w = words[i];
        while (w != 0) {
            uint64_t t = w & (~w + 1);
            int r = __builtin_ctzll(w);
            out[outpos++] = r + base;
            w ^= t;
        }
        base += 64;
    }
    return outpos;
}

#if defined(CROARING_ASMBITMANIPOPTIMIZATION) && defined(CROARING_IS_X64)

static inline uint64_t _asm_bitset_set_list_withcard(uint64_t *words, uint64_t card,
                                  const uint16_t *list, uint64_t length) {
    uint64_t offset, load, pos;
    uint64_t shift = 6;
    const uint16_t *end = list + length;
    if (!length) return card;
    // TODO: could unroll for performance, see bitset_set_list
    // bts is not available as an intrinsic in GCC
    __asm volatile(
        "1:\n"
        "movzwq (%[list]), %[pos]\n"
        "shrx %[shift], %[pos], %[offset]\n"
        "mov (%[words],%[offset],8), %[load]\n"
        "bts %[pos], %[load]\n"
        "mov %[load], (%[words],%[offset],8)\n"
        "sbb $-1, %[card]\n"
        "add $2, %[list]\n"
        "cmp %[list], %[end]\n"
        "jnz 1b"
        : [card] "+&r"(card), [list] "+&r"(list), [load] "=&r"(load),
          [pos] "=&r"(pos), [offset] "=&r"(offset)
        : [end] "r"(end), [words] "r"(words), [shift] "r"(shift));
    return card;
}

static inline void _asm_bitset_set_list(uint64_t *words, const uint16_t *list, uint64_t length) {
    uint64_t pos;
    const uint16_t *end = list + length;

    uint64_t shift = 6;
    uint64_t offset;
    uint64_t load;
    for (; list + 3 < end; list += 4) {
        pos = list[0];
        __asm volatile(
            "shrx %[shift], %[pos], %[offset]\n"
            "mov (%[words],%[offset],8), %[load]\n"
            "bts %[pos], %[load]\n"
            "mov %[load], (%[words],%[offset],8)"
            : [load] "=&r"(load), [offset] "=&r"(offset)
            : [words] "r"(words), [shift] "r"(shift), [pos] "r"(pos));
        pos = list[1];
        __asm volatile(
            "shrx %[shift], %[pos], %[offset]\n"
            "mov (%[words],%[offset],8), %[load]\n"
            "bts %[pos], %[load]\n"
            "mov %[load], (%[words],%[offset],8)"
            : [load] "=&r"(load), [offset] "=&r"(offset)
            : [words] "r"(words), [shift] "r"(shift), [pos] "r"(pos));
        pos = list[2];
        __asm volatile(
            "shrx %[shift], %[pos], %[offset]\n"
            "mov (%[words],%[offset],8), %[load]\n"
            "bts %[pos], %[load]\n"
            "mov %[load], (%[words],%[offset],8)"
            : [load] "=&r"(load), [offset] "=&r"(offset)
            : [words] "r"(words), [shift] "r"(shift), [pos] "r"(pos));
        pos = list[3];
        __asm volatile(
            "shrx %[shift], %[pos], %[offset]\n"
            "mov (%[words],%[offset],8), %[load]\n"
            "bts %[pos], %[load]\n"
            "mov %[load], (%[words],%[offset],8)"
            : [load] "=&r"(load), [offset] "=&r"(offset)
            : [words] "r"(words), [shift] "r"(shift), [pos] "r"(pos));
    }

    while (list != end) {
        pos = list[0];
        __asm volatile(
            "shrx %[shift], %[pos], %[offset]\n"
            "mov (%[words],%[offset],8), %[load]\n"
            "bts %[pos], %[load]\n"
            "mov %[load], (%[words],%[offset],8)"
            : [load] "=&r"(load), [offset] "=&r"(offset)
            : [words] "r"(words), [shift] "r"(shift), [pos] "r"(pos));
        list++;
    }
}

static inline uint64_t _asm_bitset_clear_list(uint64_t *words, uint64_t card, const uint16_t *list,
                           uint64_t length) {
    uint64_t offset, load, pos;
    uint64_t shift = 6;
    const uint16_t *end = list + length;
    if (!length) return card;
    // btr is not available as an intrinsic in GCC
    __asm volatile(
        "1:\n"
        "movzwq (%[list]), %[pos]\n"
        "shrx %[shift], %[pos], %[offset]\n"
        "mov (%[words],%[offset],8), %[load]\n"
        "btr %[pos], %[load]\n"
        "mov %[load], (%[words],%[offset],8)\n"
        "sbb $0, %[card]\n"
        "add $2, %[list]\n"
        "cmp %[list], %[end]\n"
        "jnz 1b"
        : [card] "+&r"(card), [list] "+&r"(list), [load] "=&r"(load),
          [pos] "=&r"(pos), [offset] "=&r"(offset)
        : [end] "r"(end), [words] "r"(words), [shift] "r"(shift)
        :
        /* clobbers */ "memory");
    return card;
}

static inline uint64_t _scalar_bitset_clear_list(uint64_t *words, uint64_t card, const uint16_t *list,
                           uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *(const uint16_t *)list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load & ~(UINT64_C(1) << index);
        card -= (load ^ newload) >> index;
        words[offset] = newload;
        list++;
    }
    return card;
}

static inline uint64_t _scalar_bitset_set_list_withcard(uint64_t *words, uint64_t card,
                                  const uint16_t *list, uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load | (UINT64_C(1) << index);
        card += (load ^ newload) >> index;
        words[offset] = newload;
        list++;
    }
    return card;
}

static inline void _scalar_bitset_set_list(uint64_t *words, const uint16_t *list, uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load | (UINT64_C(1) << index);
        words[offset] = newload;
        list++;
    }
}

static uint64_t bitset_clear_list(uint64_t *words, uint64_t card, const uint16_t *list,
                           uint64_t length) {
    if( croaring_avx2() ) {
        return _asm_bitset_clear_list(words, card, list, length);
    } else {
        return _scalar_bitset_clear_list(words, card, list, length);
    }
}

static uint64_t bitset_set_list_withcard(uint64_t *words, uint64_t card,
                                  const uint16_t *list, uint64_t length) {
    if( croaring_avx2() ) {
        return _asm_bitset_set_list_withcard(words, card, list, length);
    } else {
        return _scalar_bitset_set_list_withcard(words, card, list, length);
    }
}

static void bitset_set_list(uint64_t *words, const uint16_t *list, uint64_t length) {
    if( croaring_avx2() ) {
        _asm_bitset_set_list(words, list, length);
    } else {
        _scalar_bitset_set_list(words, list, length);
    }
}
#else
static uint64_t bitset_clear_list(uint64_t *words, uint64_t card, const uint16_t *list,
                           uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *(const uint16_t *)list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load & ~(UINT64_C(1) << index);
        card -= (load ^ newload) >> index;
        words[offset] = newload;
        list++;
    }
    return card;
}

static uint64_t bitset_set_list_withcard(uint64_t *words, uint64_t card,
                                  const uint16_t *list, uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load | (UINT64_C(1) << index);
        card += (load ^ newload) >> index;
        words[offset] = newload;
        list++;
    }
    return card;
}

static void bitset_set_list(uint64_t *words, const uint16_t *list, uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load | (UINT64_C(1) << index);
        words[offset] = newload;
        list++;
    }
}

#endif

/* flip specified bits */
/* TODO: consider whether worthwhile to make an asm version */

static uint64_t bitset_flip_list_withcard(uint64_t *words, uint64_t card,
                                   const uint16_t *list, uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load ^ (UINT64_C(1) << index);
        // todo: is a branch here all that bad?
        card +=
            (1 - 2 * (((UINT64_C(1) << index) & load) >> index));  // +1 or -1
        words[offset] = newload;
        list++;
    }
    return card;
}

static void bitset_flip_list(uint64_t *words, const uint16_t *list, uint64_t length) {
    uint64_t offset, load, newload, pos, index;
    const uint16_t *end = list + length;
    while (list != end) {
        pos = *list;
        offset = pos >> 6;
        index = pos % 64;
        load = words[offset];
        newload = load ^ (UINT64_C(1) << index);
        words[offset] = newload;
        list++;
    }
}

#ifdef __cplusplus
} } }  // extern "C" { namespace roaring { namespace internal {
#endif
/* end file src/bitset_util.c */
