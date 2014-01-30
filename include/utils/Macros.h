/*
 * Copyright (C) 2013 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifdef __clang__
#ifndef ANDROID_MACROS_H
#define ANDROID_MACROS_H

// A macro to disallow the copy constructor and operator= functions
// This should be used in the private: declarations for a class
// 
// For disallowing only assign or copy, write the code directly, but declare
// the intend in a comment, for example:
// void operator=(const TypeName&);  // DISALLOW_ASSIGN
// Note, that most uses of DISALLOW_ASSIGN and DISALLOW_COPY are broken
// semantically, one should either use disallow both or neither. Try to
// avoid these in new code.
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
  TypeName(const TypeName&);               \
  void operator=(const TypeName&)

// An older, politically incorrect name for the above.
// Prefer DISALLOW_COPY_AND_ASSIGN for new code.
#define DISALLOW_EVIL_CONSTRUCTORS(TypeName) DISALLOW_COPY_AND_ASSIGN(TypeName)

// A macro to disallow all the implicit constructors, namely the
// default constructor, copy constructor and operator= functions.
//
// This should be used in the private: declarations for a class
// that wants to prevent anyone from instantiating it. This is
// especially useful for classes containing only static methods.
#define DISALLOW_IMPLICIT_CONSTRUCTORS(TypeName) \
  TypeName();                                    \
  DISALLOW_COPY_AND_ASSIGN(TypeName)

#endif
#endif
