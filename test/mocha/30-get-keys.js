/*
 * Copyright (c) 2016 Digital Bazaar, Inc. All rights reserved.
 */
/* globals describe, it, should, beforeEach */
/* jshint node: true */
'use strict';

var async = require('async');
var bedrock = require('bedrock');
var brKey = require('bedrock-key');
var config = bedrock.config;
var helpers = require('./helpers');
var mockData = require('./mock.data');
var request = require('request');
request = request.defaults({json: true, strictSSL: false});
var url = require('url');

var urlObj = {
  protocol: 'https',
  host: config.server.host,
  pathname: config.key.basePath
};

describe('bedrock-key-http API: getPublicKeys', function() {
  beforeEach(done => {
    helpers.prepareDatabase(mockData, done);
  });

  describe('authenticated as regularUser', () => {
    var mockIdentity = mockData.identities.regularUser;

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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(mockIdentity.identity.id);
          callback();
        }]
      }, done);
    });

    it('should return multiple public keys', done => {
      var samplePublicKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = mockIdentity.identity.id;

      async.auto({
        insert: function(callback) {
          async.series([
            callback => {brKey.addPublicKey(null, samplePublicKey, callback)}
          ], callback);
        },
        get: ['insert', callback => {
          urlObj.query = {owner: mockIdentity.identity.id};
          request.get(helpers.createHttpSignatureRequest({
            url: url.format(urlObj),
            identity: mockIdentity
          }), (err, res) => {
            callback(err, res);
          });
        }],
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          results.get.body.should.have.length(2);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(mockIdentity.identity.id);
          result[1].publicKeyPem.should.equal(
            samplePublicKey.publicKeyPem);
          result[1].owner.should.equal(mockIdentity.identity.id);
          callback();
        }]
      }, done);
    });

    it('should return the correct publicKey with sign capability', done => {
      var samplePublicKey = {};
      var privateKey = {};

      samplePublicKey.publicKeyPem = mockData.goodKeyPair.publicKeyPem;
      samplePublicKey.owner = mockIdentity.identity.id;
      privateKey.privateKeyPem = mockData.goodKeyPair.privateKeyPem;

      async.auto({
        insert: function(callback) {
          brKey.addPublicKey(null, samplePublicKey, privateKey, callback);
          callback();
        },
        get: ['insert', callback => {
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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(samplePublicKey.publicKeyPem);
          result[0].owner.should.equal(mockIdentity.identity.id);
          callback();
        }]
      }, done);
    });

    it('should return nothing when public key is not found', done => {
      var invalidActorId = mockIdentity.identity.id + 1;

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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          results.get.body.should.have.length(0);
          callback();
        }]
      }, done);
    });

    it('should return a valid public key for a different actor', done => {
      var mockIdentity2 = mockData.identities.regularUser2;

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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
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
    var mockIdentity = mockData.identities.adminUser;
    var actor = mockIdentity.identity;

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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
          results.get.body.should.have.length(1);
          result[0].publicKeyPem.should.equal(
            mockIdentity.keys.publicKey.publicKeyPem);
          result[0].owner.should.equal(actor.id);
          callback();
        }]
      }, done);
    });

    it('should return a valid public key for a different actor', done => {
      var mockIdentity2 = mockData.identities.regularUser2;

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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
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
    var mockIdentity = mockData.identities.noPermissionUser;
    var actor = mockIdentity.identity;

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
        test: ['get', (callback, results, err) => {
          should.not.exist(err);
          results.get.statusCode.should.equal(200);
          var result = results.get.body;
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
      request.get(url.format(urlObj), function(err, res, body) {
        res.statusCode.should.equal(200);
        should.exist(res.body);
        res.body.should.have.length(0);
        done();
      });
    });

  }); // no authentication

});
