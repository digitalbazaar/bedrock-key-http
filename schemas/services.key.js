/*
 * Copyright (c) 2012-2015 Digital Bazaar, Inc. All rights reserved.
 */
var constants = require('bedrock').config.constants;
var schemas = require('bedrock-validation').schemas;

var postKey = {
  type: 'object',
  properties: {
    '@context': schemas.jsonldContext(constants.IDENTITY_CONTEXT_V1_URL),
    id: schemas.identifier(),
    label: schemas.label({required: false}),
    revoked: {
      required: false,
      type: 'string'
    }
  },
  additionalProperties: false
};

var getKeysQuery = {
  title: 'Get Keys Query',
  type: 'object',
  properties: {
    owner: schemas.identifier({required: true}),
  }
};

var postKeys = {
  type: 'object',
  properties: {
    '@context': schemas.jsonldContext(constants.IDENTITY_CONTEXT_V1_URL),
    label: schemas.label(),
    owner: schemas.identifier({
      required: false
    }),
    publicKeyPem: schemas.publicKeyPem(),
    privateKeyPem: schemas.privateKeyPem({required: false})
  },
  additionalProperties: false
};

module.exports.postKey = function() {
  return postKey;
};
module.exports.getKeysQuery = function() {
  return getKeysQuery;
};
module.exports.postKeys = function() {
  return postKeys;
};
