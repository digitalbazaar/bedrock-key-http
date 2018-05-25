/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
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

describe('bedrock-key-http API: getPublicKeys', () => {
  beforeEach(done => {
    helpers.prepareDatabase(mockData, done);
  });

  describe('authenticated as regularUser', () => {
    const mockIdentity = mockData.identities.regularUser;

    it('should return a valid public key for an actor w/ id', done => {
      async.auto({
        get: callback => {
          urlObj.query = {owner: mockIdentity.identity.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(mockIdentity.identity.id);
          callback();
        }]
      }, done);
    });

    it('should return multiple public keys', done => {
      const samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = mockIdentity.identity.id;

      async.auto({
        insert: callback => brKey.addPublicKey(null, samplePublicKey, callback),
        get: ['insert', (results, callback) => {
          urlObj.query = {owner: mockIdentity.identity.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          result.should.have.length(2);
          const keyMaterial = result.map(k => k.publicKeyPem);
          keyMaterial.should.have.same.members([
            mockIdentity.keys.publicKey.publicKeyPem,
            samplePublicKey.publicKeyPem
          ]);
          const owners = result.map(k => k.owner);
          owners.every(o => o === mockIdentity.identity.id).should.be.true;
          callback();
        }]
      }, done);
    });

    it('should return the correct publicKey with sign capability', done => {
      const samplePublicKey = {};
      const privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = mockIdentity.identity.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: callback => brKey.addPublicKey(
          null, samplePublicKey, privateKey, callback),
        get: ['insert', (results, callback) => {
          urlObj.query = {
            owner: mockIdentity.identity.id,
            capability: 'sign'
          };
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
          result[0].owner.should.equal(mockIdentity.identity.id);
          callback();
        }]
      }, done);
    });

    it('should return nothing when public key is not found', done => {
      const invalidActorId = mockIdentity.identity.id + 1;

      async.auto({
        get: callback => {
          urlObj.query = {owner: invalidActorId};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          results.get.body.should.have.length(0);
          callback();
        }]
      }, done);
    });

    it('should return a valid public key for a different actor', done => {
      const mockIdentity2 = mockData.identities.regularUser2;

      async.auto({
        get: callback => {
          urlObj.query = {owner: mockIdentity.identity.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity2
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(mockIdentity.identity.id);
          callback();
        }]
      }, done);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const mockIdentity = mockData.identities.adminUser;
    const actor = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', done => {
      async.auto({
        get: callback => {
          urlObj.query = {owner: actor.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(actor.id);
          callback();
        }]
      }, done);
    });

    it('should return a valid public key for a different actor', done => {
      const mockIdentity2 = mockData.identities.regularUser2;

      async.auto({
        get: callback => {
          urlObj.query = {owner: mockIdentity2.identity.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity2.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(
            mockIdentity2.identity.id);
          callback();
        }]
      }, done);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const mockIdentity = mockData.identities.noPermissionUser;
    const actor = mockIdentity.identity;

    it('should return a valid public key for an actor w/ id', done => {
      async.auto({
        get: callback => {
          urlObj.query = {owner: actor.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        },
        test: ['get', (results, callback) => {
          results.get.statusCode.should.equal(200);
          const result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(actor.id);
          callback();
        }]
      }, done);
    });

  }); // noPermissionUser

  describe('user with no authentication', () => {

    it('should return nothing for a non authenticated owner', done => {
      urlObj.query = {owner: 'foo'};
      request.get(url.format(urlObj), (err, res) => {
        res.statusCode.should.equal(200);
        should.exist(res.body);
        res.body.should.have.length(0);
        done();
      });
    });

  }); // no authentication

});
