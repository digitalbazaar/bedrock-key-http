/*
 * Copyright (c) 2012-2018 Digital Bazaar, Inc. All rights reserved.
 */
const {constants} = require('bedrock').config;
const {schemas} = require('bedrock-validation');

const postKey = {
  type: 'object',
  properties: {
    '@context': schemas.jsonldContext(
      constants.SECURITY_CONTEXT_V2_URL, {required: false}),
    id: schemas.identifier(),
    label: schemas.label({required: false}),
    revoked: {
      required: false,
      type: 'string'
    }
  },
  additionalProperties: false
};

const getKeysQuery = {
  title: 'Get Keys Query',
  type: 'object',
  properties: {
    owner: schemas.identifier({required: true})
  },
  additionalProperties: false
};

const rsaKey = {
  title: 'RSA Verification Key',
  type: 'object',
  properties: {
    '@context': schemas.jsonldContext(
      constants.SECURITY_CONTEXT_V2_URL, {required: false}),
    type: {
      type: 'string',
      enum: ['RsaVerificationKey2018'],
      required: true
    },
    label: schemas.label(),
    owner: schemas.identifier(),
    publicKeyPem: schemas.publicKeyPem(),
    privateKeyPem: schemas.privateKeyPem({required: false})
  },
  additionalProperties: false
};

const ed25519Key = {
  title: 'Ed25519 Verification Key',
  type: 'object',
  properties: {
    '@context': schemas.jsonldContext(
      constants.SECURITY_CONTEXT_V2_URL, {required: false}),
    type: {
      type: 'string',
      enum: ['Ed25519VerificationKey2018'],
      required: true
    },
    label: schemas.label(),
    owner: schemas.identifier(),
    // FIXME: improve validation
    publicKeyBase58: {
      type: 'string',
      required: true
    },
    // FIXME: include in security/v2 context (or transitively via security v1)
    privateKeyBase58: {
      type: 'string',
      required: false
    }
  },
  additionalProperties: false
};

const postKeys = {
  type: [rsaKey, ed25519Key]
};

module.exports.postKey = () => postKey;
module.exports.getKeysQuery = () => getKeysQuery;
module.exports.postKeys = () => postKeys;
