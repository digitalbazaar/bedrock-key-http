/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const bedrock = require('bedrock');
const brKey = require('bedrock-key');
const {config} = bedrock;
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

const GET = promisify(request.get);

describe('bedrock-key-http API: getPublicKey', () => {
  beforeEach(async () => {
    helpers.prepareDatabase(mockData);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;
    const keyOwner = mockIdentity.identity;

    it('should return a public key for an owner using key id', async () => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      await brKey.addPublicKey(
        {actor: null, privateKey, publicKey: samplePublicKey});

      const response = GET(helpers.createHttpSignatureRequest({
        url: samplePublicKey.id,
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
      body.owner.should.equal(keyOwner.id);
      should.not.exist(keyOwner.privateKey);
    });

    it('should return a public key for another actor using key id',
      async () => {
      const samplePublicKey = {};
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondOwner = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondOwner.id;

      await brKey.addPublicKey({actor: null, publicKey: samplePublicKey});

      const response = await GET(helpers.createHttpSignatureRequest({
        url: samplePublicKey.id,
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
      body.owner.should.equal(secondOwner.id);
      should.not.exist(body.privateKey);
    });

    it('should return nothing if key not found', async () => {
      const samplePublicKey = {};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;

      await brKey.addPublicKey({actor: null, publicKey: samplePublicKey});
      const response = await GET(helpers.createHttpSignatureRequest({
        url: (samplePublicKey.id + 1),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(404);
      should.exist(response.body);
      response.body.should.be.an('object');
      should.exist(response.body.type);
      response.body.type.should.equal('NotFoundError');
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', async () => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      await brKey.addPublicKey(
        {actor: null, privateKey, publicKey: samplePublicKey});

      const response = GET(helpers.createHttpSignatureRequest({
        url: samplePublicKey.id,
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
      body.owner.should.equal(keyOwner.id);
      should.not.exist(body.privateKey);
    });

    it('should return a public key for another actor using key id',
      async () => {
      const samplePublicKey = {};
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondOwner = mockIdentity2.identity;

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = secondOwner.id;

      await brKey.addPublicKey({actor: null, publicKey: samplePublicKey});

      const response = await GET(helpers.createHttpSignatureRequest({
        url: samplePublicKey.id,
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
      body.owner.should.equal(secondOwner.id);
      should.not.exist(body.privateKey);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const keyOwner = mockIdentity.identity;

    it('should return a public key for an actor using key id', async () => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = keyOwner.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      await brKey.addPublicKey(
        {actor: null, privateKey, publicKey: samplePublicKey});

      const response = GET(helpers.createHttpSignatureRequest({
        url: samplePublicKey.id,
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.publicKeyPem.should.equal(mockData.goodKeyPair.publicKeyPem);
      body.owner.should.equal(keyOwner.id);
      should.not.exist(body.privateKey);
    });

  }); // noPermissionUser

  describe('User with no authentication', () => {

    it('should return error for nonauthenticated ID (no Key)', async () => {
      urlObj.pathname += '/99';
      const response = GET(url.format(urlObj));
      response.statusCode.should.equal(404);
      should.exist(response.body.type);
      response.body.type.should.equal('NotFoundError');
    });

  }); // no authentication

});
