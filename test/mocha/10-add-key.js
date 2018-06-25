/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const {config} = bedrock;
const database = require('bedrock-mongodb');
const helpers = require('./helpers');
const mockData = require('./mock.data');
let request = require('request');
request = request.defaults({json: true, strictSSL: false});
const {promisify} = require('util');
const url = require('url');

const urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: config.key.basePath
};

const POST = promisify(request.post);

const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';

describe('bedrock-key-http API: addPublicKey', () => {
  beforeEach(async () => {
    await helpers.prepareDatabase(mockData);
  });

  describe('authenticated as regularUser', () => {
    const keyOwner = mockData.identities.regularUser;

    it('should add a valid public key with no private key', async () => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/security/v2',
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      let result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        keyOwner.keys.publicKey.publicKeyPem);

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(201);

      result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(2);
      result[1].publicKey.publicKeyPem.should.equal(
        newKey.publicKeyPem);
      should.not.exist(result[1].publicKey.privateKey);
    });

    it('should add a valid public key with matching private key', async () => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      let result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        keyOwner.keys.publicKey.publicKeyPem);

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(201);

      result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(2);
      result[1].publicKey.publicKeyPem.should.equal(
        newKey.publicKeyPem);
      should.exist(result[1].publicKey.privateKey);
      result[1].publicKey.privateKey.privateKeyPem.should.equal(
        newKey.privateKeyPem);
    });

    it('should return error if adding public key w/ bad private key',
      async () => {
      const newKey = mockData.badKeyPair;
      const samplePublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(400);
      response.body.cause.type.should.equal('SyntaxError');
    });

    it('should return error if owner id does not match', async () => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner.identity.id + 1,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(400);
      response.body.cause.type.should.equal('PermissionDenied');
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const keyOwner = mockData.identities.adminUser;

    it('should add a valid public key for self', async () => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      let result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        keyOwner.keys.publicKey.publicKeyPem);

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(201);

      result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(2);
      result[1].publicKey.publicKeyPem.should.equal(
        newKey.publicKeyPem);
      should.not.exist(result[1].publicKey.privateKey);
    });

    it('should add a valid public key for another user', async () => {
      const keyOwner2 = mockData.identities.regularUser;
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner2.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      let result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        keyOwner.keys.publicKey.publicKeyPem);

      result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner2.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(1);
      result[0].publicKey.publicKeyPem.should.equal(
        keyOwner2.keys.publicKey.publicKeyPem);

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(201);

      result = await database.collections.publicKey.find(
        {'publicKey.owner': keyOwner2.identity.id}).toArray();
      should.exist(result);
      result.should.have.length(2);
      result[1].publicKey.publicKeyPem.should.equal(
        newKey.publicKeyPem);
      should.not.exist(result[1].publicKey.privateKey);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const keyOwner = mockData.identities.noPermissionUser;

    it(
      'should return error when adding public key w/o permissions', async () => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        label: 'Signing Key 1',
        owner: keyOwner.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      const response = await POST(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        body: samplePublicKey,
        identity: keyOwner
      }));
      response.statusCode.should.equal(400);
      response.body.cause.type.should.equal('PermissionDenied');
    });

  }); // noPermissionUser

  describe('user with no authentication', async () => {

    it('should return error when not authenticated', async () => {
      const response = await POST(url.format(urlObj));
      response.statusCode.should.equal(400);
      should.exist(response.body);
      response.body.should.be.an('object');
      should.exist(response.body.type);
      response.body.type.should.equal('NotAllowedError');
    });

  }); // no authentication

});
