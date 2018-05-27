/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const brIdentity = require('bedrock-identity');
const brKey = require('bedrock-key');
const database = require('bedrock-mongodb');
const uuid = require('uuid/v4');

const api = {};
module.exports = api;

api.createHttpSignatureRequest = options => {
  const newRequest = {
    url: options.url,
    httpSignature: {
      key: options.identity.keys.privateKey.privateKeyPem,
      keyId: options.identity.keys.publicKey.id,
      headers: ['date', 'host', '(request-target)']
    }
  };
  if(options.body) {
    newRequest.body = options.body;
  }
  return newRequest;
};

api.createIdentity = userName => {
  const newIdentity = {
    id: 'did:' + uuid(),
    type: 'Identity',
    sysSlug: userName,
    label: userName,
    email: userName + '@bedrock.dev',
    sysPassword: 'password',
    sysPublic: ['label', 'url', 'description'],
    sysResourceRole: [],
    url: 'https://example.com',
    description: userName,
    sysStatus: 'active'
  };
  return newIdentity;
};

api.removeCollection = (collection, callback) => {
  const collectionNames = [collection];
  database.openCollections(collectionNames, () => {
    async.each(collectionNames, (collectionName, callback) => {
      database.collections[collectionName].remove({}, callback);
    }, err => {
      callback(err);
    });
  });
};

api.removeCollections = callback => {
  const collectionNames = ['identity', 'eventLog', 'publicKey'];
  database.openCollections(collectionNames, () => {
    async.each(collectionNames, (collectionName, callback) => {
      database.collections[collectionName].remove({}, callback);
    }, err => callback(err));
  });
};

api.createKeyPair = options => {
  const userName = options.userName;
  const publicKey = options.publicKey;
  const privateKey = options.privateKey;
  let ownerId = null;
  if(userName === 'userUnknown') {
    ownerId = '';
  } else {
    ownerId = options.userId;
  }
  const newKeyPair = {
    publicKey: {
      '@context': 'https://w3id.org/identity/v1',
      id: ownerId + '/keys/1',
      type: ['CryptographicKey', 'RsaVerificationKey2018'],
      owner: ownerId,
      label: 'Signing Key 1',
      publicKeyPem: publicKey
    },
    privateKey: {
      type: 'CryptographicKey',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKey: ownerId + '/keys/1',
      privateKeyPem: privateKey
    }
  };
  return newKeyPair;
};

api.prepareDatabase = (mockData, callback) => {
  async.series([
    callback => api.removeCollections(callback),
    callback => insertTestData(mockData, callback)
  ], callback);
};

// Insert identities and public keys used for testing into database
function insertTestData(mockData, callback) {
  async.forEachOf(mockData.identities, (identity, key, callback) => {
    const {publicKey} = identity.keys;
    async.parallel([
      callback => brIdentity.insert(null, identity.identity, callback),
      callback => brKey.addPublicKey({actor: null, publicKey}, callback)
    ], callback);
  }, err => {
    if(err) {
      if(!database.isDuplicateError(err)) {
        // duplicate error means test data is already loaded
        return callback(err);
      }
    }
    callback();
  }, callback);
}
