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

const POST = promisify(request.post);

const SECURITY_V2_CONTEXT = 'https://w3id.org/security/v2';

describe('bedrock-key-http API: Update PublicKey (postPublicKey)', () => {
  beforeEach(async () => {
    helpers.prepareDatabase(mockData);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;
    const keyOwner = mockIdentity.identity;

    it('should update a public key for an actor using key id', async () => {
      const originalPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'SigningKey00'
      };

      const original = await brKey.addPublicKey(
        {actor: null, publicKey: originalPublicKey});
      const queryPublicKey = {id: originalPublicKey.id};
      await brKey.getPublicKey({actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        id: originalPublicKey.id,
        label: 'SigningKey01'
      };
      await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = original;
      const {publicKey: finalPublicKey} = final;
      origPublicKey.label.should.equal(originalPublicKey.label);
      finalPublicKey.label.should.equal(newPublicKey.label);
      origPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      finalPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      origPublicKey.owner.should.equal(keyOwner.id);
      finalPublicKey.owner.should.equal(keyOwner.id);
      original.meta.status.should.equal(final.meta.status);
    });

    it('should return error for mismatched key id', async () => {
      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey({actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        id: originalPublicKey.id + 1,
        label: 'SigningKey01'
      };
      const response = await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      response.statusCode.should.equal(400);
      response.body.message.should.equal('Incorrect key id.');
      finalPublicKey.label.should.equal(origPublicKey.label);
      finalPublicKey.publicKeyPem.should.equal(origPublicKey.publicKeyPem);
    });

    it('should revoke a public key using the key id', async () => {
      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey({actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        id: originalPublicKey.id,
        label: 'SigningKey01',
        revoked: 'revoke'
      };
      const response = POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      response.statusCode.should.equal(200);
      origPublicKey.label.should.equal(originalPublicKey.label);
      finalPublicKey.label.should.equal(originalPublicKey.label);
      origPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      finalPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      origPublicKey.owner.should.equal(keyOwner.id);
      finalPublicKey.owner.should.equal(keyOwner.id);
      orig.meta.status.should.equal('active');
      final.meta.status.should.equal('disabled');
      should.not.exist(origPublicKey.revoked);
      should.exist(finalPublicKey.revoked);
    });

    it('should do nothing if there are no fields to update', async () => {
      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey({actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        id: originalPublicKey.id
      };
      const response = await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      response.statusCode.should.equal(204);
      origPublicKey.label.should.equal(originalPublicKey.label);
      finalPublicKey.label.should.equal(originalPublicKey.label);
      origPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      finalPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      origPublicKey.owner.should.equal(keyOwner.id);
      finalPublicKey.owner.should.equal(keyOwner.id);
      origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
    });

    it('should return error if key id is not found', async () => {
      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey(
        {actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        id: originalPublicKey.id + 1,
        label: 'SigningKey01'
      };
      const response = await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id + 1,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      response.statusCode.should.equal(404);
      response.body.type.should.equal('NotFoundError');
      finalPublicKey.label.should.equal(origPublicKey.label);
      finalPublicKey.publicKeyPem.should.equal(origPublicKey.publicKeyPem);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const keyOwner = mockIdentity.identity;

    it('should update a public key for an actor using key id', async () => {
      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: keyOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey(
        {actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        id: originalPublicKey.id,
        label: 'SigningKey01'
      };
      await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      origPublicKey.label.should.equal(originalPublicKey.label);
      finalPublicKey.label.should.equal(newPublicKey.label);
      origPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      finalPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      origPublicKey.owner.should.equal(keyOwner.id);
      finalPublicKey.owner.should.equal(keyOwner.id);
      origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
    });

    it('should update public key for a different actor using key id',
      async () => {
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondOwner = mockIdentity2.identity;

      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: secondOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey(
        {actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        id: originalPublicKey.id,
        label: 'SigningKey01'
      };
      await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      origPublicKey.label.should.equal(originalPublicKey.label);
      finalPublicKey.label.should.equal(newPublicKey.label);
      origPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      finalPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      origPublicKey.owner.should.equal(secondOwner.id);
      finalPublicKey.owner.should.equal(secondOwner.id);
      orig.meta.status.should.equal(final.meta.status);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const keyOwner = mockIdentity.identity;

    it('should return error when updating public key w/o permissions',
      async () => {
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondOwner = mockIdentity2.identity;

      const originalPublicKey = {
        type: 'RsaVerificationKey2018',
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: secondOwner.id,
        label: 'SigningKey00'
      };

      await brKey.addPublicKey(
        {actor: null, publicKey: originalPublicKey});

      const queryPublicKey = {id: originalPublicKey.id};
      const orig = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const newPublicKey = {
        '@context': SECURITY_V2_CONTEXT,
        id: originalPublicKey.id,
        label: 'SigningKey01'
      };
      const response = await POST(helpers.createHttpSignatureRequest({
        url: originalPublicKey.id,
        body: newPublicKey,
        identity: mockIdentity
      }));

      const final = await brKey.getPublicKey(
        {actor: null, publicKey: queryPublicKey});

      const {publicKey: origPublicKey} = orig;
      const {publicKey: finalPublicKey} = final;
      response.statusCode.should.equal(403);
      response.body.type.should.equal('PermissionDenied');
      origPublicKey.label.should.equal(originalPublicKey.label);
      finalPublicKey.label.should.equal(originalPublicKey.label);
      origPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      finalPublicKey.publicKeyPem.should.equal(
        originalPublicKey.publicKeyPem);
      origPublicKey.owner.should.equal(secondOwner.id);
      finalPublicKey.owner.should.equal(secondOwner.id);
      origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
    });

  }); // noPermissionUser

  describe('user with no authentication', () => {

    it('should return error for nonauthenticated ID (no Key)', async () => {
      urlObj.pathname += '/99';
      const response = await POST(url.format(urlObj));
      response.statusCode.should.equal(400);
      should.exist(response.body.type);
      response.body.type.should.equal('NotAllowedError');
    });

  }); // no authentication

});
