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

describe('bedrock-key-http API: getPublicKeys', () => {
  beforeEach(async () => {
    helpers.prepareDatabase(mockData);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;

    it('should return a valid public key for an actor w/ id', async () => {
      urlObj.query = {owner: mockIdentity.identity.id};
      const response = GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(1);
      body[0].publicKeyPem.should.equal(
        mockIdentity.keys.publicKey.publicKeyPem);
      body[0].owner.should.equal(mockIdentity.identity.id);
    });

    it('should return multiple public keys', async () => {
      const samplePublicKey = {};
      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = mockIdentity.identity.id;

      await brKey.addPublicKey({actor: null, publicKey: samplePublicKey});

      urlObj.query = {owner: mockIdentity.identity.id};
      const response = await GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(2);
      const keyMaterial = body.map(k => k.publicKeyPem);
      keyMaterial.should.have.same.members([
        mockIdentity.keys.publicKey.publicKeyPem,
        samplePublicKey.publicKeyPem
      ]);
      const owners = body.map(k => k.owner);
      owners.every(o => o === mockIdentity.identity.id).should.be.true;
    });

    it('should return the correct publicKey with sign capability', async () => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = mockIdentity.identity.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      await brKey.addPublicKey(
        {actor: null, privateKey, publicKey: samplePublicKey});

      urlObj.query = {
        owner: mockIdentity.identity.id,
        capability: 'sign'
      };
      const response = GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(1);
      body[0].publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
      body[0].owner.should.equal(mockIdentity.identity.id);
    });

    it('should return nothing when public key is not found', async () => {
      const invalidKeyOwnerId = mockIdentity.identity.id + 1;

      urlObj.query = {owner: invalidKeyOwnerId};
      const response = await GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      response.body.should.have.length(0);
    });

    it('should return a valid public key for a different actor', async () => {
      const mockIdentity2 = mockData.identities.regularUser2;

      urlObj.query = {owner: mockIdentity.identity.id};
      const response = await GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity2
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(1);
      body[0].publicKeyPem.should.equal(
        mockIdentity.keys.publicKey.publicKeyPem);
      body[0].owner.should.equal(mockIdentity.identity.id);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', async () => {
      urlObj.query = {owner: keyOwner.id};
      const response = GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(1);
      body[0].publicKeyPem.should.equal(
        mockIdentity.keys.publicKey.publicKeyPem);
      body[0].owner.should.equal(keyOwner.id);
    });

    it('should return a valid public key for a different actor', async () => {
      const mockIdentity2 = mockData.identities.regularUser2;

      urlObj.query = {owner: mockIdentity2.identity.id};
      const response = GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(1);
      body[0].publicKeyPem.should.equal(
        mockIdentity2.keys.publicKey.publicKeyPem);
      body[0].owner.should.equal(
        mockIdentity2.identity.id);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const actor = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', async () => {
      urlObj.query = {owner: actor.id};
      const response = GET(helpers.createHttpSignatureRequest({
        url: url.format(urlObj),
        identity: mockIdentity
      }));
      response.statusCode.should.equal(200);
      const {body} = response;
      body.should.have.length(1);
      body[0].publicKeyPem.should.equal(
        mockIdentity.keys.publicKey.publicKeyPem);
      body[0].owner.should.equal(actor.id);
    });

  }); // noPermissionUser

  describe('user with no authentication', () => {

    it('should return nothing for a non authenticated owner', async () => {
      urlObj.query = {owner: 'foo'};
      const response = await GET(url.format(urlObj));
      response.statusCode.should.equal(200);
      should.exist(response.body);
      response.body.should.have.length(0);
    });

  }); // no authentication

});
