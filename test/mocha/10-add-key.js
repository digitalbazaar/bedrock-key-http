/*
 * Copyright (c) 2016-2018 Digital Bazaar, Inc. All rights reserved.
 */
/* globals should */
'use strict';

const async = require('async');
const bedrock = require('bedrock');
const config = bedrock.config;
const database = require('bedrock-mongodb');
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

describe('bedrock-key-http API: addPublicKey', () => {
  beforeEach(done => helpers.prepareDatabase(mockData, done));

  describe('authenticated as regularUser', () => {
    const actor = mockData.identities.regularUser;

    it('should add a valid public key with no private key', done => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      async.auto({
        insert: callback => async.series([
          callback => database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
            callback();
          }),
          callback => request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            res.statusCode.should.equal(201);
            callback(err, res);
          })
        ], callback),
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.not.exist(result[1].publicKey.privateKey);
            callback();
          });
        }]
      }, done);
    });

    it('should add a valid public key with matching private key', done => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: callback => async.series([
          callback => database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
            callback();
          }),
          callback => request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            res.statusCode.should.equal(201);
            callback(err, res);
          })
        ], callback),
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.exist(result[1].publicKey.privateKey);
            result[1].publicKey.privateKey.privateKeyPem.should.equal(
              newKey.privateKeyPem);
            callback();
          });
        }]
      }, done);
    });

    it('should return error if adding public key w/ bad private key', done => {
      const newKey = mockData.badKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: callback => request.post(helpers.createHttpSignatureRequest({
          url: url.format(urlObj),
          body: samplePublicKey,
          identity: actor
        }), (err, res) => {
          callback(err, res);
        }),
        test: ['insert', (results, callback) => {
          results.insert.statusCode.should.equal(400);
          results.insert.body.cause.type.should.equal('InvalidKeyPair');
          callback();
        }]
      }, done);
    });

    it('should return error if owner id does not match', done => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id + 1,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: callback => request.post(helpers.createHttpSignatureRequest({
          url: url.format(urlObj),
          body: samplePublicKey,
          identity: actor
        }), (err, res) => {
          callback(err, res);
        }),
        test: ['insert', (results, callback) => {
          results.insert.statusCode.should.equal(400);
          results.insert.body.cause.type.should.equal('PermissionDenied');
          callback();
        }]
      }, done);
    });

  }); // regular user

  describe('authenticated as adminUser', () => {
    const actor = mockData.identities.adminUser;

    it('should add a valid public key for self', done => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      async.auto({
        insert: callback => async.series([
          callback => database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
            callback();
          }),
          callback => request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            res.statusCode.should.equal(201);
            callback(err, res);
          })
        ], callback),
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.not.exist(result[1].publicKey.privateKey);
            callback();
          });
        }]
      }, done);
    });

    it('should add a valid public key for another user', done => {
      const actor2 = mockData.identities.regularUser;
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor2.identity.id,
        publicKeyPem: newKey.publicKeyPem
      };

      async.auto({
        insert: callback => async.series([
          callback => database.collections.publicKey.find({
            'publicKey.owner': actor.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor.keys.publicKey.publicKeyPem);
            callback();
          }),
          callback => database.collections.publicKey.find({
            'publicKey.owner': actor2.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(1);
            result[0].publicKey.publicKeyPem.should.equal(
              actor2.keys.publicKey.publicKeyPem);
            callback();
          }),
          callback => request.post(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            body: samplePublicKey,
            identity: actor
          }), (err, res) => {
            res.statusCode.should.equal(201);
            callback(err, res);
          })
        ], callback),
        test: ['insert', (results, callback) => {
          database.collections.publicKey.find({
            'publicKey.owner': actor2.identity.id
          }).toArray((err, result) => {
            should.not.exist(err);
            should.exist(result);
            result.should.have.length(2);
            result[1].publicKey.publicKeyPem.should.equal(
              newKey.publicKeyPem);
            should.not.exist(result[1].publicKey.privateKey);
            callback();
          });
        }]
      }, done);
    });

  }); // admin user

  describe('authenticated as user with no permissions', () => {
    const actor = mockData.identities.noPermissionUser;

    it('should return error when adding public key w/o permissions', done => {
      const newKey = mockData.goodKeyPair;
      const samplePublicKey = {
        '@context': 'https://w3id.org/identity/v1',
        label: 'Signing Key 1',
        owner: actor.identity.id,
        publicKeyPem: newKey.publicKeyPem,
        privateKeyPem: newKey.privateKeyPem
      };

      async.auto({
        insert: callback => request.post(helpers.createHttpSignatureRequest({
          url: url.format(urlObj),
          body: samplePublicKey,
          identity: actor
        }), (err, res) => {
          callback(err, res);
        }),
        test: ['insert', (results, callback) => {
          results.insert.statusCode.should.equal(400);
          results.insert.body.cause.type.should.equal('PermissionDenied');
          callback();
        }]
      }, done);
    });

  }); // noPermissionUser

  describe('user with no authentication', () => {

    it('should return error when not authenticated', done => {
      request.post(url.format(urlObj), (err, res, body) => {
        res.statusCode.should.equal(400);
        should.exist(body);
        body.should.be.an('object');
        should.exist(body.type);
        body.type.should.equal('PermissionDenied');
        done();
      });
    });

  }); // no authentication

});
