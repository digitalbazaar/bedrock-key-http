/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const brIdentity = require('bedrock-identity');
const brKey = require('bedrock-key');
const database = require('bedrock-mongodb');
const {promisify} = require('util');
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
    id: 'did:example:' + uuid(),
    label: userName,
    email: userName + '@bedrock.dev',
    url: 'https://example.com',
    description: userName
  };
  return newIdentity;
};

api.removeCollection =
  async collectionName => api.removeCollections([collectionName]);

api.removeCollections = async (collectionNames = [
  'identity', 'publicKey', 'eventLog']) => {
  await promisify(database.openCollections)(collectionNames);
  for(const collectionName of collectionNames) {
    await database.collections[collectionName].remove({});
  }
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
      type: 'RsaVerificationKey2018',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKeyPem: publicKey
    },
    privateKey: {
      type: 'RsaSignatureKey2018',
      owner: ownerId,
      label: 'Signing Key 1',
      publicKey: ownerId + '/keys/1',
      privateKeyPem: privateKey
    }
  };
  return newKeyPair;
};

api.prepareDatabase = async mockData => {
  await api.removeCollections();
  await insertTestData(mockData);
};

async function insertTestData(mockData) {
  const records = Object.values(mockData.identities);
  for(const record of records) {
    try {
      await Promise.all([
        brIdentity.insert(
          {actor: null, identity: record.identity, meta: record.meta || {}}),
        brKey.addPublicKey(
          {actor: null, publicKey: record.keys.publicKey})
      ]);
    } catch(e) {
      if(e.name === 'DuplicateError') {
        // duplicate error means test data is already loaded
        continue;
      }
      throw e;
    }
  }
}
