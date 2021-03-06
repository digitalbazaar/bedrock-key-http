/*
 * Copyright (c) 2016-2017 Digital Bazaar, Inc. All rights reserved.
 */
/* globals should */
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
      let orig;
      let final;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results) => {
          orig = results.readOrig;
          final = results.readUpdate;
          orig[0].label.should.equal(originalPublicKey.label);
          final[0].label.should.equal(newPublicKey.label);
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig[0].owner.should.equal(actor.id);
          final[0].owner.should.equal(actor.id);
          orig[0].sysStatus.should.equal(final[0].sysStatus);
          callback();
        }]
      }, done);
    });

    it('should return error for mismatched key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let final;
      let orig;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results) => {
          result = results.update[0];
          orig = results.readOrig;
          final = results.readUpdate;
          result.statusCode.should.equal(400);
          result.body.message.should.equal('Incorrect key id.');
          final[0].label.should.equal(orig[0].label);
          final[0].publicKeyPem.should.equal(orig[0].publicKeyPem);
          callback();
        }]
      }, done);
    });

    it('should revoke a public key using the key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let final;
      let orig;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)
        ],
        test: ['readUpdate', (callback, results) => {
          result = results.update[0];
          orig = results.readOrig[0];
          final = results.readUpdate[0];
          result.statusCode.should.equal(200);
          orig.label.should.equal(originalPublicKey.label);
          final.label.should.equal(originalPublicKey.label);
          orig.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig.owner.should.equal(actor.id);
          final.owner.should.equal(actor.id);
          orig.sysStatus.should.equal('active');
          final.sysStatus.should.equal('disabled');
          should.not.exist(orig.revoked);
          should.exist(final.revoked);
          callback();
        }]
      }, done);
    });

    it('should do nothing if there are no fields to update', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let orig;
      let final;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results) => {
          result = results.update[0];
          orig = results.readOrig[0];
          final = results.readUpdate[0];
          result.statusCode.should.equal(204);
          orig.label.should.equal(originalPublicKey.label);
          final.label.should.equal(originalPublicKey.label);
          orig.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig.owner.should.equal(actor.id);
          final.owner.should.equal(actor.id);
          orig.sysStatus.should.equal(final.sysStatus);
          callback();
        }]
      }, done);
    });

    it('should return error if key id is not found', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let final;
      let orig;
      let result;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results) => {
          result = results.update[0];
          orig = results.readOrig;
          final = results.readUpdate;
          result.statusCode.should.equal(404);
          result.body.type.should.equal('NotFound');
          final[0].label.should.equal(orig[0].label);
          final[0].publicKeyPem.should.equal(orig[0].publicKeyPem);
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
      let orig;
      let final;
      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: actor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results) => {
          orig = results.readOrig;
          final = results.readUpdate;
          orig[0].label.should.equal(originalPublicKey.label);
          final[0].label.should.equal(newPublicKey.label);
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig[0].owner.should.equal(actor.id);
          final[0].owner.should.equal(actor.id);
          orig[0].sysStatus.should.equal(final[0].sysStatus);
          callback();
        }]
      }, done);
    });

    it('should update public key for a different actor using key id', done => {
      let newPublicKey = {};
      let queryPublicKey;
      let orig;
      let final;
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = mockIdentity2.identity;

      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: secondActor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results) => {
          orig = results.readOrig;
          final = results.readUpdate;
          orig[0].label.should.equal(originalPublicKey.label);
          final[0].label.should.equal(newPublicKey.label);
          orig[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final[0].publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig[0].owner.should.equal(secondActor.id);
          final[0].owner.should.equal(secondActor.id);
          orig[0].sysStatus.should.equal(final[0].sysStatus);
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
      let orig;
      let final;
      const mockIdentity2 = mockData.identities.regularUser2;
      const secondActor = mockIdentity2.identity;

      const originalPublicKey = {
        publicKeyPem: mockData.goodKeyPair.publicKeyPem,
        owner: secondActor.id,
        label: 'SigningKey00'
      };

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, originalPublicKey, callback),
        readOrig: ['insert', callback => {
          queryPublicKey = {id: originalPublicKey.id};
          brKey.getPublicKey(queryPublicKey, actor, callback);
        }],
        update: ['readOrig', callback => {
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
        readUpdate: ['update', callback => brKey.getPublicKey(
          queryPublicKey, actor, callback)],
        test: ['readUpdate', (callback, results, err) => {
          const result = results.update[0];
          orig = results.readOrig[0];
          final = results.readUpdate[0];
          should.not.exist(err);
          result.statusCode.should.equal(403);
          result.body.type.should.equal('PermissionDenied');
          orig.label.should.equal(originalPublicKey.label);
          final.label.should.equal(originalPublicKey.label);
          orig.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          final.publicKeyPem.should.equal(
            originalPublicKey.publicKeyPem);
          orig.owner.should.equal(secondActor.id);
          final.owner.should.equal(secondActor.id);
          orig.sysStatus.should.equal(final.sysStatus);
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
