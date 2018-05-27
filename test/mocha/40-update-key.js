/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const brKey = require('bedrock-key');
const config = bedrock.config;
const helpers = require('./helpers');
const mockData = require('./mock.data');
let request = require('request');
request = request.defaults({json: true, strictSSL: false});
const url = require('url');

const urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: config.key.basePath
};

describe('bedrock-key-http API: Update PublicKey (postPublicKey)', () => {
  beforeEach(done => {
    helpers.prepareDatabase(mockData, done);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;
    const actor = mockIdentity.identity;

    it('should update a public key for an actor using key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id,
            label: 'SigningKey01'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(newPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(actor.id);
          finalPublicKey.owner.should.equal(actor.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
          callback();
        }]
      }, done);
    });

    it('should return error for mismatched key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id + 1,
            label: 'SigningKey01'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          result = results.update[0];
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          result.statusCode.should.equal(400);
          result.body.message.should.equal('Incorrect key id.');
          finalPublicKey.label.should.equal(origPublicKey.label);
          finalPublicKey.publicKeyPem.should.equal(origPublicKey.publicKeyPem);
          callback();
        }]
      }, done);
    });

    it('should revoke a public key using the key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id,
            label: 'SigningKey01',
            revoked: 'revoke'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          result = results.update[0];
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          result.statusCode.should.equal(200);
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(originalPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(actor.id);
          finalPublicKey.owner.should.equal(actor.id);
          origPublicKey.sysStatus.should.equal('active');
          finalPublicKey.sysStatus.should.equal('disabled');
          should.not.exist(origPublicKey.revoked);
          should.exist(finalPublicKey.revoked);
          callback();
        }]
      }, done);
    });

    it('should do nothing if there are no fields to update', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          result = results.update[0];
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          result.statusCode.should.equal(204);
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(originalPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(actor.id);
          finalPublicKey.owner.should.equal(actor.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
          callback();
        }]
      }, done);
    });

    it('should return error if key id is not found', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id + 1,
            label: 'SigningKey01'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id + 1,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          result = results.update[0];
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          result.statusCode.should.equal(404);
          result.body.type.should.equal('NotFoundError');
          finalPublicKey.label.should.equal(origPublicKey.label);
          finalPublicKey.publicKeyPem.should.equal(origPublicKey.publicKeyPem);
          callback();
        }]
      }, done);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const actor = mockIdentity.identity;

    it('should update a public key for an actor using key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id,
            label: 'SigningKey01'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(newPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(actor.id);
          finalPublicKey.owner.should.equal(actor.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
          callback();
        }]
      }, done);
    });

    it('should update public key for a different actor using key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = mockIdentity2.identity;

      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: secondActor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id,
            label: 'SigningKey01'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(newPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(secondActor.id);
          finalPublicKey.owner.should.equal(secondActor.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
          callback();
        }]
      }, done);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const actor = mockIdentity.identity;

    it('should return error when updating public key w/o permissions', done => {
      let newPublicKey = {};
      let queryPublicKey;
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = mockIdentity2.identity;

      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: secondActor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          {actor: null, publicKey: originalPublicKey}, callback),
        orig: ['insert', (results, callback) => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey({actor, publicKey: queryPublicKey}, callback);
        }],
        update: ['orig', (results, callback) => {
          newPublicKey = {
            '@context': 'https://w3id.org/identity/v1',
            id: originalPublicKey.id,
            label: 'SigningKey01'
          };
          request.post(helpers.createHttpSignatureRequest({
            url: originalPublicKey.id,
            body: newPublicKey,
            identity: mockIdentity
          }), callback);
        }],
        final: ['update', (results, callback) => brKey.getPublicKey(
          {actor, publicKey: queryPublicKey}, callback)],
        test: ['final', (results, callback) => {
          const result = results.update[0];
          const {orig, final} = results;
          const {publicKey: origPublicKey} = orig;
          const {publicKey: finalPublicKey} = final;
          result.statusCode.should.equal(403);
          result.body.type.should.equal('PermissionDenied');
          origPublicKey.label.should.equal(originalPublicKey.label);
          finalPublicKey.label.should.equal(originalPublicKey.label);
          origPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          finalPublicKey.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          origPublicKey.owner.should.equal(secondActor.id);
          finalPublicKey.owner.should.equal(secondActor.id);
          origPublicKey.sysStatus.should.equal(finalPublicKey.sysStatus);
          callback();
        }]
      }, done);
    });

  }); // noPermissionUser

  describe('user with no authentication', () => {

    it('should return error for nonauthenticated ID (no Key)', done => {
      urlObj.pathname += '/99';
      request.post(url.format(urlObj), (err, res, body) => {
        res.statusCode.should.equal(400);
        should.exist(body.type);
        body.type.should.equal('PermissionDenied');
        done();
      });
    });

  }); // no authentication

});
