/*
 * Copyright (c) 2020 Contributors to the Eclipse Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef biscuit_bindings_h
#define biscuit_bindings_h


#define BISCUIT_AUTH_MAJOR 6
#define BISCUIT_AUTH_MINOR 0
#define BISCUIT_AUTH_PATCH 0


#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef enum ErrorKind {
  None,
  InvalidArgument,
  InternalError,
  FormatSignatureInvalidFormat,
  FormatSignatureInvalidSignature,
  FormatSealedSignature,
  FormatEmptyKeys,
  FormatUnknownPublicKey,
  FormatDeserializationError,
  FormatSerializationError,
  FormatBlockDeserializationError,
  FormatBlockSerializationError,
  FormatVersion,
  FormatInvalidBlockId,
  FormatExistingPublicKey,
  FormatSymbolTableOverlap,
  FormatPublicKeyTableOverlap,
  FormatUnknownExternalKey,
  FormatUnknownSymbol,
  AppendOnSealed,
  LogicInvalidBlockRule,
  LogicUnauthorized,
  LogicAuthorizerNotEmpty,
  LogicNoMatchingPolicy,
  LanguageError,
  TooManyFacts,
  TooManyIterations,
  Timeout,
  ConversionError,
  FormatInvalidKeySize,
  FormatInvalidSignatureSize,
  FormatInvalidKey,
  FormatSignatureDeserializationError,
  FormatBlockSignatureDeserializationError,
  FormatSignatureInvalidSignatureGeneration,
  AlreadySealed,
  Execution,
  UnexpectedQueryResult,
  FormatPKCS8,
} ErrorKind;

typedef enum SignatureAlgorithm {
  Ed25519,
  Secp256r1,
} SignatureAlgorithm;

typedef struct Authorizer Authorizer;

typedef struct AuthorizerBuilder AuthorizerBuilder;

typedef struct Biscuit Biscuit;

typedef struct BiscuitBuilder BiscuitBuilder;

typedef struct BlockBuilder BlockBuilder;

typedef struct KeyPair KeyPair;

typedef struct PublicKey PublicKey;

const char *error_message(void);

enum ErrorKind error_kind(void);

uint64_t error_check_count(void);

uint64_t error_check_id(uint64_t check_index);

uint64_t error_check_block_id(uint64_t check_index);

/**
 * deallocation is handled by Biscuit
 * the string is overwritten on each call
 */
const char *error_check_rule(uint64_t check_index);

bool error_check_is_authorizer(uint64_t check_index);

struct KeyPair *key_pair_new(const uint8_t *seed_ptr,
                             uintptr_t seed_len,
                             enum SignatureAlgorithm algorithm);

struct PublicKey *key_pair_public(const struct KeyPair *kp);

/**
 * expects a 32 byte buffer
 */
uintptr_t key_pair_serialize(const struct KeyPair *kp, uint8_t *buffer_ptr);

/**
 * expects a 32 byte buffer
 */
struct KeyPair *key_pair_deserialize(uint8_t *buffer_ptr, enum SignatureAlgorithm algorithm);

const char *key_pair_to_pem(const struct KeyPair *kp);

struct KeyPair *key_pair_from_pem(const char *pem);

void key_pair_free(struct KeyPair *_kp);

/**
 * expects a 32 byte buffer
 */
uintptr_t public_key_serialize(const struct PublicKey *kp, uint8_t *buffer_ptr);

/**
 * expects a 32 byte buffer
 */
struct PublicKey *public_key_deserialize(uint8_t *buffer_ptr, enum SignatureAlgorithm algorithm);

const char *public_key_to_pem(const struct PublicKey *kp);

struct PublicKey *public_key_from_pem(const char *pem);

bool public_key_equals(const struct PublicKey *a, const struct PublicKey *b);

void public_key_free(struct PublicKey *_kp);

struct BiscuitBuilder *biscuit_builder(void);

bool biscuit_builder_set_context(struct BiscuitBuilder *builder, const char *context);

bool biscuit_builder_set_root_key_id(struct BiscuitBuilder *builder, uint32_t root_key_id);

bool biscuit_builder_add_fact(struct BiscuitBuilder *builder, const char *fact);

bool biscuit_builder_add_rule(struct BiscuitBuilder *builder, const char *rule);

bool biscuit_builder_add_check(struct BiscuitBuilder *builder, const char *check);

/**
 * Build a biscuit token from a builder
 *
 * The builder will be freed automatically when the biscuit is returned
 */
struct Biscuit *biscuit_builder_build(const struct BiscuitBuilder *builder,
                                      const struct KeyPair *key_pair,
                                      const uint8_t *seed_ptr,
                                      uintptr_t seed_len);

void biscuit_builder_free(struct BiscuitBuilder *_builder);

struct Biscuit *biscuit_from(const uint8_t *biscuit_ptr,
                             uintptr_t biscuit_len,
                             const struct PublicKey *root);

uintptr_t biscuit_serialized_size(const struct Biscuit *biscuit);

uintptr_t biscuit_sealed_size(const struct Biscuit *biscuit);

uintptr_t biscuit_serialize(const struct Biscuit *biscuit, uint8_t *buffer_ptr);

uintptr_t biscuit_serialize_sealed(const struct Biscuit *biscuit, uint8_t *buffer_ptr);

uintptr_t biscuit_block_count(const struct Biscuit *biscuit);

char *biscuit_block_context(const struct Biscuit *biscuit, uint32_t block_index);

struct BlockBuilder *create_block(void);

struct Biscuit *biscuit_append_block(const struct Biscuit *biscuit,
                                     const struct BlockBuilder *block_builder,
                                     const struct KeyPair *key_pair);

struct Authorizer *biscuit_authorizer(const struct Biscuit *biscuit);

void biscuit_free(struct Biscuit *_biscuit);

bool block_builder_set_context(struct BlockBuilder *builder, const char *context);

bool block_builder_add_fact(struct BlockBuilder *builder, const char *fact);

bool block_builder_add_rule(struct BlockBuilder *builder, const char *rule);

bool block_builder_add_check(struct BlockBuilder *builder, const char *check);

void block_builder_free(struct BlockBuilder *_builder);

struct AuthorizerBuilder *authorizer_builder(void);

bool authorizer_builder_add_fact(struct AuthorizerBuilder *builder, const char *fact);

bool authorizer_builder_add_rule(struct AuthorizerBuilder *builder, const char *rule);

bool authorizer_builder_add_check(struct AuthorizerBuilder *builder, const char *check);

bool authorizer_builder_add_policy(struct AuthorizerBuilder *builder, const char *policy);

/**
 * Build an authorizer
 *
 * The builder will be freed automatically when the authorizer is returned
 */
struct Authorizer *authorizer_builder_build(struct AuthorizerBuilder *builder,
                                            const struct Biscuit *token);

/**
 * Build an authorizer without a token
 *
 * The builder will be freed automatically when the authorizer is returned
 */
struct Authorizer *authorizer_builder_build_unauthenticated(struct AuthorizerBuilder *builder);

void authorizer_builder_free(struct AuthorizerBuilder *_builder);

bool authorizer_authorize(struct Authorizer *authorizer);

char *authorizer_print(struct Authorizer *authorizer);

void authorizer_free(struct Authorizer *_authorizer);

void string_free(char *ptr);

const char *biscuit_print(const struct Biscuit *biscuit);

const char *biscuit_print_block_source(const struct Biscuit *biscuit, uint32_t block_index);

#endif  /* biscuit_bindings_h */
